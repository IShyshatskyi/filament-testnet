// src/common/genesis/genesis.rs - UPDATED for Phase 3b: beacon genesis coinbase transaction
//
// CHANGES (Phase 3b — beacon coinbase):
// 1. create_genesis_coinbase now builds a real Transaction:
//      - No inputs (is_coinbase() == true; verify_transactions() always passes)
//      - Output 0: OP_RETURN commitment (value = 0, provably unspendable)
//          script = [0x6a] ++ anchor_height (u32 LE, 4 B)
//                          ++ anchor_hash (32 B)
//                          ++ msg_len (u8, 1 B)
//                          ++ genesis_message bytes (N B)
//      - Outputs 1..N: one TxOutput per PremineOutput entry (if any)
// 2. generate_beacon_genesis uses BeaconBlock::calculate_merkle_root (txid-based
//    SHA256 tree) instead of the old private Self::calculate_merkle_root, which
//    used SHA256(b"tx" || version || locktime) as the leaf hash — inconsistent
//    with how verify_transactions and validate_beacon_genesis check the root.
// 3. generate_beacon_genesis uses BeaconBlock::with_transactions so that
//    genesis.transactions is populated; removed the now-redundant manual
//    `genesis.hash = BeaconBlock::calculate_hash(...)` line.
// 4. validate_beacon_genesis now checks:
//      - First transaction is coinbase (no inputs) when transactions are present
//      - Coinbase has at least one output (the OP_RETURN commitment)
//      - Header merkle_root == crate::common::blocks::shard_block::ShardBlockBody::from_transactions(transactions, None).calculate_tx_merkle_root()
//    These checks are skipped when block.transactions is empty, which is the
//    case for v1/v2 blocks deserialized from storage (#[serde(default)]).
// 5. Removed dead private methods: calculate_merkle_root, hash_transaction,
//    double_sha256
// 6. Removed dead imports: sha2::{Sha256, Digest}, bitcoin_anchors, sha256d
//
// EARLIER CHANGES (legacy_linear_cumulative_difficulty — kept intact):
// 1. Genesis beacon block sets legacy_linear_cumulative_difficulty = difficulty
// 2. Genesis shard block validates chain_weight = difficulty (already correct)
// 3. validate_beacon_genesis and validate_shard_genesis enforce those rules

use crate::common::blocks::beacon_block::{BeaconBlockCandidateHeader, BeaconBlock};
use super::genesis_config::{BeaconGenesisConfig, PremineOutput};
use crate::transaction::{Transaction, TxOutput};
use crate::common::blocks::shard_block::address_string_to_recipient;
use crate::common::orange_tree::OrangeTreeEncoding;
use crate::common::weighted_mmr_core::WeightedMMR;
use crate::common::crypto::weighted_hash::WeightedHash;

pub struct GenesisGenerator;

impl GenesisGenerator {
    /// Generate beacon genesis block from configuration.
    ///
    /// The block carries a real coinbase transaction whose txid-based merkle
    /// root is committed in the header.  All subsequent blocks must follow the
    /// same merkle convention (BeaconBlock::calculate_merkle_root) so that
    /// verify_transactions and validate_beacon_genesis remain consistent.
    ///
    /// RULE 2: Genesis legacy_linear_cumulative_difficulty = difficulty (no parent).
    pub fn generate_beacon_genesis(
        config: &BeaconGenesisConfig,
    ) -> Result<BeaconBlock, String> {
        config.validate_premine()?;

        let coinbase = Self::create_genesis_coinbase(
            &config.premine,
            &config.genesis_message,
            &config.bitcoin_anchor_hash,
            config.bitcoin_anchor_height,
        )?;

        let transactions = vec![coinbase];

        // Convert to flat body first so we can compute the BLAKE3-based
        // tx_merkle_root before hashing the header (tx_merkle_root is inside
        // the commitment hash which feeds PoW).
        let mut body = crate::common::blocks::shard_block::ShardBlockBody::from_transactions(
            &transactions,
            None,
        );

        // CB-1/CB-2 (Stratum_Extranonce_Binding_Plan.md §2): every beacon
        // coinbase carries a miner-extranonce extension, genesis included —
        // "genesis has no Stratum session" means a fixed [0u8;8] payload, not
        // an absent extension, so `validate_beacon_block_structure_v3`
        // (which requires one to derive `coinbase_hash`) has no genesis
        // special-case to carry.
        //
        // Must happen *before* `calculate_tx_merkle_root()` below — the
        // extension changes the coinbase's txid, hence the merkle root;
        // computing the root first and attaching the extension after (the
        // bug in an earlier version of this edit) leaves `header.tx_merkle_root`
        // permanently stale relative to the real stored body, failing
        // `validate_beacon_genesis`'s own tx_merkle_root cross-check for
        // every network on the very first load.
        let extranonce_ext = crate::transaction::build_miner_extranonce_extension([0u8; 4], [0u8; 4]);
        body.extensions.push(extranonce_ext);
        if let Some(desc) = body.descriptors.get_mut(0) {
            desc.extension_len = desc.extension_len.saturating_add(1);
        }

        let merkle_root = body.calculate_tx_merkle_root();

        let mut header = BeaconBlockCandidateHeader::new(
            config.version,
            config.timestamp,
            0,                                          // height 0 for genesis
            config.bits,
            WeightedHash::from(config.bitcoin_anchor_hash), // prev_mmr_root = Bitcoin anchor
            merkle_root,
            [0u8; 32],                  // no merged mining root for genesis
            config.bitcoin_anchor_timestamp,
        );

        header.nonce = config.nonce.unwrap_or(0);

        // v3 (plan §3.1): genesis's own coinbase_hash, derived from its real
        // stored body — same formula every other beacon block now uses, so
        // this cached `.hash` field and `validate_beacon_block_structure_v3`
        // (run against the stored block later) never diverge. See
        // share_processor.rs's own fix for the exact class of bug this avoids:
        // a block's cached `.hash` computed via one formula while validation
        // recomputes via another.
        let coinbase_hash = crate::transaction::coinbase_hash_from_stored_body(&body)
            .expect("genesis coinbase always has the extension just attached above");
        let hash = BeaconBlock::calculate_weighted_hash_v3(&header, coinbase_hash);
        let mut genesis = BeaconBlock { header, hash, body };

        // Compute current_mmr_root using WeightedMMR so it is consistent with
        // what BeaconChain appends on chain load.
        genesis.header.current_mmr_root = {
            let mut mmr = WeightedMMR::new_with_config(config);
            mmr.append(genesis.hash).0
        };

        // RULE 2: Genesis block has non-zero legacy_linear_cumulative_difficulty.
        genesis.header.legacy_linear_cumulative_difficulty = config.difficulty as u128;

        if let Some(expected_hash) = config.expected_hash {
            // BV-PROTO-1 VF-9: `expected_hash` is pinned in *weighted* form
            // (SHA256d bytes 0..28 + rBits in 28..32 — what `genesis_miner`
            // prints and what the P2P chain identity advertises), so compare
            // the weighted hash. Comparing the plain SHA256d here failed for
            // every pinned genesis (testnet-stress), aborting node startup.
            let weighted: [u8; 32] = genesis.hash.into();
            if weighted != expected_hash {
                return Err(format!(
                    "Generated genesis hash {} doesn't match expected {}",
                    hex::encode(weighted),
                    hex::encode(expected_hash),
                ));
            }
        }

        Ok(genesis)
    }

    /// The beacon genesis block hash for `config` — the chain's P2P identity.
    ///
    /// The genesis block's **weighted** hash (`BeaconBlock::hash`: SHA256d
    /// bytes 0–27 + rBits in bytes 28–31) — the same form
    /// `BeaconGenesisConfig::expected_hash` is pinned in, and the value
    /// Keystone's `ChainProvider::genesis_params()` already reports. A pure
    /// function of the genesis config (no chain state), so every node on the
    /// same genesis computes the same bytes without holding block 0 in RAM.
    ///
    /// Generated with `expected_hash` cleared, so the identity is computed
    /// from the config alone even when the pin is wrong — startup rejects a
    /// wrong pin separately. (The pin check itself compared the plain hash
    /// against the weighted pin and rejected every pinned config until VF-9
    /// was fixed.)
    ///
    /// Advertised in the ShishaNet `VersionMessage` (wire v11+) so peers on a
    /// different chain that happens to share a network name are refused at
    /// handshake — BV-PROTO-1 VF-7, see `network_identity`.
    pub fn beacon_genesis_hash(config: &BeaconGenesisConfig) -> Result<[u8; 32], String> {
        let mut unpinned = config.clone();
        unpinned.expected_hash = None;
        let genesis = Self::generate_beacon_genesis(&unpinned)?;
        Ok(<[u8; 32]>::from(genesis.hash))
    }

    /// Build the genesis coinbase transaction.
    ///
    /// The coinbase has no inputs (`is_coinbase()` returns true; it always
    /// passes `verify_transactions` regardless of UTXO set contents).
    ///
    /// **Output 0 — OP_RETURN genesis commitment (value = 0)**
    ///
    /// The script embeds an unforgeable external timestamp via the Bitcoin
    /// block hash plus the human-readable genesis message:
    ///
    /// ```text
    /// [0x6a]  OP_RETURN opcode
    /// [4 B]   bitcoin_anchor_height (u32 little-endian)
    /// [32 B]  bitcoin_anchor_hash
    /// [1 B]   genesis_message length
    /// [N B]   genesis_message bytes
    /// ```
    ///
    /// 0x6a is OP_RETURN; the output is provably unspendable.  Scripts are
    /// opaque byte sequences in this codebase — no Bitcoin Script evaluation
    /// is performed.
    ///
    /// **Outputs 1..N — premine allocations**
    ///
    /// One `TxOutput` per `PremineOutput` entry in the genesis config.
    /// `value` is the premine amount in satoshis.
    ///
    /// > **TODO**: when the wallet module exposes address → P2PKH/P2WPKH
    /// > script conversion, replace `entry.address.as_bytes()` with the
    /// > proper script encoding.
    fn create_genesis_coinbase(
        premine: &[PremineOutput],
        genesis_message: &str,
        bitcoin_anchor_hash: &[u8; 32],
        bitcoin_anchor_height: u32,
    ) -> Result<Transaction, String> {
        // Commitment data for the OP_RETURN script:
        //   anchor_height (4 LE) | anchor_hash (32) | msg_len (1) | msg_bytes (N)
        let mut commitment = Vec::with_capacity(37 + genesis_message.len());
        commitment.extend_from_slice(&bitcoin_anchor_height.to_le_bytes());
        commitment.extend_from_slice(bitcoin_anchor_hash);
        commitment.push(genesis_message.len() as u8);
        commitment.extend_from_slice(genesis_message.as_bytes());

        let mut tx = Transaction::new(1, 0);

        // Output 0: OP_RETURN genesis commitment — value 0, permanently unspendable.
        // The 32-byte recipient encodes BLAKE3(commitment_data) so that different
        // anchor heights / hashes / genesis messages produce different txids.
        // The all-zeros sentinel ([0u8;32]) is NOT used here — that would silently
        // discard the genesis parameters and make all genesis blocks identical.
        let op_return_recipient: [u8; 32] = blake3::hash(&commitment).into();
        tx.add_output(TxOutput {
            value: 0,
            recipient: op_return_recipient,
        });

        // Outputs 1..N: premine allocations.
        for entry in premine {
            tx.add_output(TxOutput {
                value: entry.amount,
                // "0x" + 64-hex addresses decode to a real spendable pubkey;
                // any other (human-label) address falls through to a BLAKE3
                // placeholder with no known key. See `address_string_to_recipient`.
                recipient: address_string_to_recipient(&entry.address),
            });
        }

        Ok(tx)
    }

    /// Validate beacon genesis block against its configuration.
    ///
    /// Checks (in order):
    /// 1. height == 0
    /// 2. prev_mmr_root == Bitcoin anchor  (prev_block_hash check removed W3-3;
    ///    both fields hold the same anchor value by convention, and prev_mmr_root
    ///    is the canonical chain-linkage field going forward)
    /// 3. current_mmr_root == hash_pair(anchor, block.hash)
    /// 4. legacy_linear_cumulative_difficulty == difficulty (RULE 2)
    /// 5. When block.transactions is non-empty:
    ///      a. transactions[0].is_coinbase()
    ///      b. coinbase has at least one output
    ///      c. header.merkle_root == calculate_merkle_root(transactions)
    /// 6. block.hash == calculate_hash(header)
    /// 7. block.hash == expected_hash (if configured)
    pub fn validate_beacon_genesis(
        block: &BeaconBlock,
        config: &BeaconGenesisConfig,
    ) -> Result<(), String> {
        if block.header.height != 0 {
            return Err(format!(
                "Genesis block height must be 0, got {}",
                block.header.height,
            ));
        }

        // W3-3: prev_block_hash check removed; prev_mmr_root == bitcoin_anchor_hash
        // is the canonical anchor invariant.  prev_block_hash holds the same value
        // by construction but is being phased out (Wave 5 removal).

        if block.header.prev_mmr_root != WeightedHash::from(config.bitcoin_anchor_hash) {
            return Err(format!(
                "Genesis prev_mmr_root must be Bitcoin anchor {}, got {}",
                hex::encode(config.bitcoin_anchor_hash),
                hex::encode(*block.header.prev_mmr_root),
            ));
        }

        let expected_mmr_root = {
            let mut mmr = WeightedMMR::new_with_config(config);
            mmr.append(block.hash).0
        };
        if block.header.current_mmr_root != expected_mmr_root {
            return Err(format!(
                "Genesis current_mmr_root must equal WeightedMMR(anchor, genesis_hash): \
                 expected {}, got {}",
                hex::encode(*expected_mmr_root),
                hex::encode(*block.header.current_mmr_root),
            ));
        }

        // ✅ RULE 2: legacy_linear_cumulative_difficulty = difficulty.
        let expected_cumulative = config.difficulty as u128;
        if block.header.legacy_linear_cumulative_difficulty != expected_cumulative {
            return Err(format!(
                "Genesis legacy_linear_cumulative_difficulty must equal difficulty: \
                 expected {}, got {}",
                expected_cumulative,
                block.header.legacy_linear_cumulative_difficulty,
            ));
        }

        // Body checks — only when the block carries transactions.
        // Blocks deserialized from v3 storage have an empty body and are skipped.
        if !block.body.descriptors.is_empty() {
            if !block.body.has_coinbase() {
                return Err(
                    "Genesis first transaction must be coinbase (no inputs)"
                        .to_string(),
                );
            }

            let first = &block.body.descriptors[0];
            let out_start = first.out_start as usize;
            let out_end = (first.out_start + first.out_len) as usize;
            if out_start >= out_end {
                return Err(
                    "Genesis coinbase must have at least one output \
                     (OP_RETURN commitment)"
                        .to_string(),
                );
            }

            let expected_merkle = block.body.calculate_tx_merkle_root();
            if block.header.tx_merkle_root != expected_merkle {
                return Err(format!(
                    "Genesis tx_merkle_root mismatch: header has {}, \
                     body computes to {}",
                    hex::encode(block.header.tx_merkle_root),
                    hex::encode(expected_merkle),
                ));
            }
        }

        // v3 (plan §3.1): genesis's coinbase carries the CB-1 miner-extranonce
        // extension the same as every other beacon block (`generate_beacon_genesis`
        // attaches it), so `coinbase_hash_from_stored_body` succeeds for a
        // genesis built by this codebase. Blocks with an empty body (the
        // pre-existing "loaded from storage, body not carried" tolerance
        // documented just above) fall back to the legacy formula, exactly as
        // this function already tolerated before v3 existed — not a new
        // exception, the same one, just spelled out for both formulas now.
        let calculated_hash = match crate::transaction::coinbase_hash_from_stored_body(&block.body) {
            Some(coinbase_hash) => BeaconBlock::calculate_weighted_hash_v3(&block.header, coinbase_hash),
            None => BeaconBlock::calculate_weighted_hash(&block.header),
        };
        if block.hash != calculated_hash {
            return Err(format!(
                "Genesis hash mismatch: stored {}, calculated {}",
                hex::encode(block.hash),
                hex::encode(calculated_hash),
            ));
        }

        if let Some(expected_hash) = config.expected_hash {
            // VF-9: weighted form, as in `generate_beacon_genesis`.
            // `block.hash` was just checked equal to the recomputed hash above.
            let weighted: [u8; 32] = block.hash.into();
            if weighted != expected_hash {
                return Err(format!(
                    "Genesis hash mismatch: expected {}, got {}",
                    hex::encode(expected_hash),
                    hex::encode(weighted),
                ));
            }
        }

        Ok(())
    }
}

/*
===============================================================================
GENESIS CUMULATIVE DIFFICULTY RULES
===============================================================================

RULE 2: Genesis block has non-zero legacy_linear_cumulative_difficulty

BEACON GENESIS:
- legacy_linear_cumulative_difficulty = difficulty (no parent to add to)
- Validated in validate_beacon_genesis()

SHARD GENESIS:
- chain_weight = difficulty (shard equivalent)
- Already correctly implemented and validated

REASONING:
Genesis has no parent, so:
  parent.legacy_linear_cumulative_difficulty = 0  (implicit)
  block.legacy_linear_cumulative_difficulty  = 0 + difficulty = difficulty

This is the base case for the cumulative difficulty chain.

===============================================================================
BEACON GENESIS COINBASE STRUCTURE
===============================================================================

Output 0 — OP_RETURN commitment (value = 0, provably unspendable)

  script_pubkey bytes:
    [0x6a]   OP_RETURN opcode
    [4 B]    bitcoin_anchor_height  (u32 little-endian)
    [32 B]   bitcoin_anchor_hash
    [1 B]    genesis_message length (u8)
    [N B]    genesis_message bytes

  Purpose: embeds an unforgeable external timestamp (via Bitcoin block hash)
           and a human-readable genesis message into the chain's first
           transaction.  Pre-mining is detectable because the coinbase txid —
           and therefore the merkle root — depends on the Bitcoin anchor hash,
           which is unknown before the anchor block exists.

Outputs 1..N — premine allocations (optional, one per PremineOutput entry)
  value        = premine amount in satoshis
  script_pubkey = address bytes (raw; TODO: proper P2PKH/P2WPKH encoding)

The coinbase has no inputs, so:
  is_coinbase()       == true
  verify_transactions() passes on any ForkUtxoOverlay (no inputs to look up)

===============================================================================
*/
#[cfg(test)]
mod pinned_genesis_tests {
    use super::super::{BeaconGenesisConfig, NetworkGenesisConfig};
    use super::GenesisGenerator;

    fn shipped_testnet_stress() -> BeaconGenesisConfig {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/genesis_testnet_stress.toml");
        NetworkGenesisConfig::from_file(&path).expect("shipped genesis parses").beacon
    }

    /// BV-PROTO-1 VF-9 (TEST-COV-1): a node starting fresh on a genesis that
    /// pins `expected_hash` must be able to generate and then validate its
    /// own genesis block. testnet-stress is the only network that pins one,
    /// in both the shipped TOML and the Rust preset.
    #[test]
    fn vf9_pinned_testnet_stress_genesis_generates_and_validates() {
        for (name, cfg) in [
            ("config/genesis_testnet_stress.toml", shipped_testnet_stress()),
            ("BeaconGenesisConfig::testnet_stress()", BeaconGenesisConfig::testnet_stress()),
        ] {
            assert!(cfg.expected_hash.is_some(), "{name}: expected a pinned hash");
            let genesis = GenesisGenerator::generate_beacon_genesis(&cfg)
                .unwrap_or_else(|e| panic!("{name}: generate: {e}"));
            GenesisGenerator::validate_beacon_genesis(&genesis, &cfg)
                .unwrap_or_else(|e| panic!("{name}: validate: {e}"));
        }
    }

    /// A pin that does not match must still be rejected by both checks.
    #[test]
    fn vf9_wrong_pin_is_rejected() {
        let good = shipped_testnet_stress();
        let genesis = GenesisGenerator::generate_beacon_genesis(&BeaconGenesisConfig {
            expected_hash: None,
            ..good.clone()
        })
        .expect("unpinned generate");
        let mut bad = good;
        let mut pin = bad.expected_hash.unwrap();
        pin[0] ^= 0xFF;
        bad.expected_hash = Some(pin);
        assert!(GenesisGenerator::generate_beacon_genesis(&bad).is_err());
        assert!(GenesisGenerator::validate_beacon_genesis(&genesis, &bad).is_err());
    }
}
