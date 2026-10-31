// genesis_config.rs - UPDATED with Bitcoin anchor constants
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::expand_voting::ExpandVotingConfig;
use crate::common::k_voting_config::KVotingConfig;

/// Default beacon:shard block-interval ratio ("chain calibration constant").
///
/// **This is not `2^asserted_s_bits` and not `2^initial_s_bits`.** True network
/// `s` (`expand_state.s_bits` / `initial_s_bits`) auto-increments as the shard
/// address space fills (Anti-Patterns Registry entry 23) and is
/// not a permanent value; using it here would silently desync shard genesis
/// difficulty from the real intended block-interval ratio the moment it
/// changes. `16` is the compile-time / serde default that matches
/// `block_intervals.rs`'s production defaults (mainnet 600s/37.5s, devnet
/// 150s/9.375s). Per-network overrides live on
/// [`BeaconGenesisConfig::shard_calibration`] (genesis TOML) and **must**
/// stay a power of two equal to
/// `beacon_interval_secs × shard_interval_den / shard_interval_num`
/// (integer-only; no floating-point). See NC-19.
pub const SHARD_CALIBRATION_CONSTANT: u64 = 16;

/// Default `shard_calibration` expressed as a left-shift amount
/// (`1 << SHARD_CALIBRATION_SHIFT_BITS == SHARD_CALIBRATION_CONSTANT`).
/// Hot paths may hardcode this when the loaded genesis uses the default 16;
/// otherwise call [`shard_calibration_shift_bits`].
pub const SHARD_CALIBRATION_SHIFT_BITS: u32 = 4;

const _: () = assert!(
    1u64 << SHARD_CALIBRATION_SHIFT_BITS == SHARD_CALIBRATION_CONSTANT,
    "SHARD_CALIBRATION_SHIFT_BITS must be log2(SHARD_CALIBRATION_CONSTANT)"
);

/// `log2(calibration)` when `calibration` is a power of two ≥ 1; else `None`.
#[inline]
pub fn shard_calibration_shift_bits(calibration: u32) -> Option<u32> {
    if calibration == 0 || !calibration.is_power_of_two() {
        return None;
    }
    Some(calibration.trailing_zeros())
}

fn default_shard_calibration() -> u32 {
    SHARD_CALIBRATION_CONSTANT as u32
}

/// Any-chain PoW floor: `2^asserted_s` (header work units / rBits decode).
///
/// Returns `None` on shift overflow (`asserted_s >= 128`).
#[inline]
pub fn beacon_any_chain_floor_u128(asserted_s: u32) -> Option<u128> {
    1u128.checked_shl(asserted_s)
}

/// Beacon PoW floor: `shard_calibration × 2^asserted_s` (Phase B / Genesis plan).
///
/// Same inequality as [`BeaconGenesisConfig::validate_difficulty_params`].
/// Returns `None` on overflow.
#[inline]
pub fn beacon_difficulty_floor_u128(shard_calibration: u32, asserted_s: u32) -> Option<u128> {
    let any = beacon_any_chain_floor_u128(asserted_s)?;
    (shard_calibration as u128).checked_mul(any)
}

/// The **one** merged beacon retarget floor
/// (Beacon_Difficulty_Unification_Design.md Principle 3 / Flaw A):
/// `max(genesis.minimum_difficulty, shard_calibration × 2^asserted_s)`.
///
/// Replaces the two floors that used to be applied separately — the DAA's own
/// `minimum_rbits` and the ad-hoc `cal × 2^s` caller clamp. Returns `None` only
/// on `cal × 2^s` overflow.
#[inline]
pub fn beacon_merged_floor_u128(
    minimum_difficulty: u64,
    shard_calibration: u32,
    asserted_s: u32,
) -> Option<u128> {
    beacon_difficulty_floor_u128(shard_calibration, asserted_s)
        .map(|cal_floor| cal_floor.max(minimum_difficulty as u128))
}

/// Bitcoin block hash constants for genesis anchoring
/// These provide external timestamps and prevent pre-mining
pub mod bitcoin_anchors {
    /// Devnet anchor: Bitcoin block 935093
    /// Hash: 00000000000000000000a2331379d2d599650753fdc982b202cb01df8299e14a
    /// Display order: 00000000000000000000a2331379d2d599650753fdc982b202cb01df8299e14a
    /// Internal order (reversed/little-endian):
    pub const DEVNET_ANCHOR_HASH: [u8; 32] = [
        0x4a, 0xe1, 0x99, 0x82, 0xdf, 0x01, 0xcb, 0x02,
        0xb2, 0x82, 0xc9, 0xfd, 0x53, 0x07, 0x65, 0x99,
        0xd5, 0xd2, 0x79, 0x13, 0x33, 0xa2, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    pub const DEVNET_ANCHOR_HEIGHT: u32 = 935093;
    
    /// Mainnet anchor - TODO: Set to actual Bitcoin block at mainnet launch
    pub const MAINNET_ANCHOR_HASH: [u8; 32] = [0u8; 32];
    pub const MAINNET_ANCHOR_HEIGHT: u32 = 0;
    
    /// Testnet1 anchor: Bitcoin block 935092
    /// Hash: 00000000000000000000c112ed1fd8be2b68298e4466566acf87ebdc669c2246
    /// Display order: 00000000000000000000c112ed1fd8be2b68298e4466566acf87ebdc669c2246
    /// Internal order (reversed/little-endian):
    pub const TESTNET1_ANCHOR_HASH: [u8; 32] = [
        0x46, 0x22, 0x9c, 0x66, 0xdc, 0xeb, 0x87, 0xcf,
        0x6a, 0x56, 0x66, 0x44, 0x8e, 0x29, 0x68, 0x2b,
        0xbe, 0xd8, 0x1f, 0xed, 0x12, 0xc1, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pub const TESTNET1_ANCHOR_HEIGHT: u32 = 935092;
    
    /// Testnet2 anchor: Bitcoin block 935091
    /// Hash: 0000000000000000000052fdf98fa31393cb0a612d4594eea37ecbd723d4d529
    /// Display order: 0000000000000000000052fdf98fa31393cb0a612d4594eea37ecbd723d4d529
    /// Internal order (reversed/little-endian):
    pub const TESTNET2_ANCHOR_HASH: [u8; 32] = [
        0x29, 0xd5, 0xd4, 0x23, 0xd7, 0xcb, 0x7e, 0xa3,
        0xee, 0x94, 0x45, 0x2d, 0x61, 0x0a, 0xcb, 0x93,
        0x13, 0xa3, 0x8f, 0xf9, 0xfd, 0x52, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pub const TESTNET2_ANCHOR_HEIGHT: u32 = 935091;

    /// Testnet-stress anchor: Bitcoin block 964050 — fixed, mined genesis
    /// (replaces the earlier devnet-anchor placeholder; see
    /// `docs/plan/Testnet_Stress_Launch_Plan.md` §3.1). This is a short-lived
    /// (≤ 30 day) stress-test network, but the anchor is now pinned for the
    /// life of this launch rather than regenerated on every soak run.
    /// Display order: 00000000000000000000b3f2b230bddf6582ae46a1a2b1fdb1a4d57691207469
    /// Internal order (reversed/little-endian):
    pub const TESTNET_STRESS_ANCHOR_HASH: [u8; 32] = [
        0x69, 0x74, 0x20, 0x91, 0x76, 0xd5, 0xa4, 0xb1,
        0xfd, 0xb1, 0xa2, 0xa1, 0x46, 0xae, 0x82, 0x65,
        0xdf, 0xbd, 0x30, 0xb2, 0xf2, 0xb3, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pub const TESTNET_STRESS_ANCHOR_HEIGHT: u32 = 964050;
}

/// Network identifier for different blockchain networks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkId {
    /// Main production network
    Mainnet,
    /// First test network
    Testnet1,
    /// Second test network
    Testnet2,
    /// Local development network
    Devnet,
    /// Testnet-stress: dedicated 30-day-cap stress/load-test network.
    /// See `docs/plan/Testnet_Stress_Launch_Plan.md`. Not for production use.
    TestnetStress,
    /// Custom network (for testing/development)
    Custom,
}

impl NetworkId {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet1 => "testnet1",
            NetworkId::Testnet2 => "testnet2",
            NetworkId::Devnet => "devnet",
            NetworkId::TestnetStress => "testnet-stress",
            NetworkId::Custom => "custom",
        }
    }

    /// Get the Bitcoin anchor hash for this network
    pub fn bitcoin_anchor_hash(&self) -> [u8; 32] {
        match self {
            NetworkId::Mainnet => bitcoin_anchors::MAINNET_ANCHOR_HASH,
            NetworkId::Testnet1 => bitcoin_anchors::TESTNET1_ANCHOR_HASH,
            NetworkId::Testnet2 => bitcoin_anchors::TESTNET2_ANCHOR_HASH,
            NetworkId::Devnet => bitcoin_anchors::DEVNET_ANCHOR_HASH,
            NetworkId::TestnetStress => bitcoin_anchors::TESTNET_STRESS_ANCHOR_HASH,
            NetworkId::Custom => bitcoin_anchors::DEVNET_ANCHOR_HASH,
        }
    }

    /// Get the Bitcoin anchor height for this network
    pub fn bitcoin_anchor_height(&self) -> u32 {
        match self {
            NetworkId::Mainnet => bitcoin_anchors::MAINNET_ANCHOR_HEIGHT,
            NetworkId::Testnet1 => bitcoin_anchors::TESTNET1_ANCHOR_HEIGHT,
            NetworkId::Testnet2 => bitcoin_anchors::TESTNET2_ANCHOR_HEIGHT,
            NetworkId::Devnet => bitcoin_anchors::DEVNET_ANCHOR_HEIGHT,
            NetworkId::TestnetStress => bitcoin_anchors::TESTNET_STRESS_ANCHOR_HEIGHT,
            NetworkId::Custom => bitcoin_anchors::DEVNET_ANCHOR_HEIGHT,
        }
    }
}

/// Premine output - funds allocated at genesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PremineOutput {
    /// Recipient address (Bitcoin-style address or identifier)
    pub address: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Optional description/purpose
    pub description: Option<String>,
}

/// Beacon genesis block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconGenesisConfig {
    /// Network identifier
    pub network_id: NetworkId,
    
    /// Genesis block version
    pub version: u32,
    
    /// Genesis block timestamp (Unix seconds)
    pub timestamp: u64,
    
    /// Genesis block difficulty **D** (primary hardness knob).
    ///
    /// Opposite of Bitcoin: here D is set in config / moved by DAA; compact
    /// `bits` encode D and the mining **target** is derived via
    /// `rbits_to_target(bits, max_target, asserted_s)`.
    pub difficulty: u64,
    
    /// Compact rBits encoding of [`Self::difficulty`] (not a Bitcoin-style primary nBits target).
    pub bits: u32,
    
    /// Bitcoin block hash to anchor genesis to
    /// This provides an external timestamp and prevents pre-mining
    /// For devnet/tests: Bitcoin block 932965
    pub bitcoin_anchor_hash: [u8; 32],
    
    /// Bitcoin block height of the anchor
    pub bitcoin_anchor_height: u32,

    /// Bitcoin block timestamp (Unix seconds) of the anchor
    ///
    /// Used as the epoch for delta (relative timestamp) calculations.
    /// All block timestamps are encoded as deltas relative to this anchor time.
    pub bitcoin_anchor_timestamp: u64,

    /// Premine outputs (if any)
    pub premine: Vec<PremineOutput>,

    /// TS-FAUCET / TS-T-10: when true, this same `premine` table is also
    /// credited (as extra coinbase outputs) on the very first block mined
    /// for each shard — shards otherwise never receive any premine (shard
    /// genesis carries zero transactions; only the beacon chain mints
    /// premine). Off by default so existing mainnet/testnet1/testnet2/devnet
    /// presets are unaffected; testnet-stress is the only preset that sets
    /// this, since its faucet/spam-wallet/treasury tooling spends premine
    /// via the shard mempool-submit path — designed before NC-36 (Jul 23,
    /// 2026) added a real beacon-chain mempool (`POST /mempool/submit/beacon`);
    /// this field predates that and was never revisited to use it instead.
    /// See `docs/plan/Testnet_Stress_Launch_Plan.md` §3.4 / TS-FAUCET.
    #[serde(default)]
    pub credit_premine_to_shard_genesis: bool,

    /// Genesis message (embedded in coinbase)
    pub genesis_message: String,
    
    /// Expected genesis block hash (for validation)
    pub expected_hash: Option<[u8; 32]>,

    /// Genesis block nonce (proof-of-work solution)
    #[serde(default)]
    pub nonce: Option<u64>,

    /// Merkle root of genesis transactions (coinbase + premine)
    pub merkle_root: Option<[u8; 32]>,

    /// Per-network **worker-safe absolute target ceiling** (256-bit softest allowed target).
    ///
    /// Legacy TOML/code field name: `max_target`. Do **not** read this as Bitcoin’s immortal
    /// “MAX_TARGET” constant — it is a **configured variable** per network (DAA scale origin).
    /// Starting hardness is genesis `difficulty` / `bits`, not this field
    /// (`validate_difficulty_params` enforces D floors against `asserted_s_bits`).
    ///
    /// Per-network ceilings (Phase A, Jul 2026):
    /// - Devnet / testnet1 / testnet-stress: ~2^232 (CPU-safe)
    /// - Mainnet / testnet2: ~2^212 (ASIC-safe)
    #[serde(default = "default_max_target")]
    pub max_target: [u8; 32],

    /// **Asserted s-bits** — difficulty-scaling exponent frozen at genesis for
    /// `calculate_difficulty_from_target`, MMR leaf weight, and job-template
    /// difficulty binding. **Not** live network hash-sorting `s`
    /// (`ExpandVotingConfig.initial_s_bits` / `EpochExpandState.s_bits`), which
    /// governs shard routing and eligibility bounds and may diverge over time.
    ///
    /// May differ from true `s` within a bounded tolerance (see
    /// `docs/plan/DAA_rBits_Native_Redesign.md` §1.2); **no deviation bound is
    /// enforced in code today** (Jul 20, 2026 gap).
    ///
    /// Legacy TOML keys: `asserted_s_bits`, `k_bits`.
    #[serde(default = "default_asserted_s_bits", alias = "asserted_s_bits", alias = "k_bits")]
    pub asserted_s_bits: u32,

    /// DAA **minimum difficulty** floor (abstract scalar).
    ///
    /// Retarget never reduces difficulty below this value. Default **64** =
    /// standard-preset beacon floor (`shard_calibration × 2^s` with cal=16, s=2).
    /// Profiles with a higher floor (e.g. testnet-stress s=4 → 256) raise this
    /// to match. ASIC firmware floors are a separate product concern (NC-21).
    #[serde(default = "default_minimum_difficulty")]
    pub minimum_difficulty: u64,

    /// Shard expansion voting parameters (consensus-critical).
    ///
    /// Governs how miners vote to open new shard chains.
    /// `#[serde(default)]` for backward compatibility with configs that
    /// predate this field — such configs get the standard 3-shard / s=2 defaults.
    #[serde(default)]
    pub shard_expansion: ExpandVotingConfig,

    /// K-coefficient voting parameters (consensus-critical).
    ///
    /// Governs how miners vote to adjust the per-epoch k-coefficient via
    /// the `vote_k_flag` bit in the block version field.
    /// `#[serde(default)]` for backward compatibility — configs that predate
    /// k-voting receive `KVotingConfig::default()` (k=1.0, 0.1% step).
    #[serde(default)]
    pub k_voting: KVotingConfig,

    /// Merged-mining tree depth — the hard capacity ceiling
    /// (`max_shards = 2^tree_depth`) that `active_shard_count`/`s_bits`
    /// (see `shard_expansion`) grow toward but must never exceed.
    ///
    /// Consensus-critical, genesis-locked (fixed Jul 11, 2026): this was
    /// previously sourced from per-node operator config
    /// (`MiningPoolConfig.merkle_tree_depth`), which let two honestly-run
    /// nodes build differently-shaped merged-mining trees for the same
    /// active shard set and compute different `merged_mining_root` values —
    /// a silent consensus fork caused purely by a local config difference.
    /// See `docs/plan/Dynamic_Shard_Activation_and_HashSorting_Design.md`
    /// §4.3/§7.2.
    ///
    /// Almost always equal to `asserted_s_bits` / `initial_s_bits`: depth `d`
    /// yields `2^d` MM leaves, and `s` addresses `2^s − 1` shards — so for
    /// the standard 3-shard / `s=2` genesis, `tree_depth = 2`. The serde
    /// default is therefore **2**. Exception: `testnet_stress` keeps
    /// `tree_depth = 4` (16 leaves) as expand-ramp headroom while initial
    /// `s` stays 2 (`3 → 7 → 15`; see Testnet Stress Launch Plan).
    ///
    /// **NC-25 / Anti-Patterns MM-7 (OPEN):** genesis-lock prevents *operator*
    /// fork, but depth must still grow with shard count / `s` over the
    /// network lifetime — no such mechanism exists yet. Do not treat this
    /// field as a permanent ceiling that expand voting can never outgrow.
    #[serde(default = "default_tree_depth")]
    pub tree_depth: u32,

    /// Beacon:shard interval calibration — must be a power of two, and must
    /// equal `beacon_interval / shard_interval` from the loaded DAA config
    /// (integer: `beacon_secs × shard_den / shard_num`). Used to widen a
    /// beacon anchor's target into a shard genesis / first-block target in
    /// target-space via a left shift (no floating-point). Default `16`.
    /// Stress profiles that deliberately use a 1:1 interval ratio (e.g.
    /// crash-recovery) set this to `1`. See NC-19 (Jul 20, 2026 decision).
    #[serde(default = "default_shard_calibration")]
    pub shard_calibration: u32,
}

/// Standard genesis difficulty stamp (Phase A — Jul 2026).
pub const GENESIS_DEFAULT_DIFFICULTY: u64 = 64;
/// Compact rBits for [`GENESIS_DEFAULT_DIFFICULTY`] (`u128_to_rbits(64)`).
pub const GENESIS_DEFAULT_BITS: u32 = 0x0300_0040;

/// CPU worker-safe initial beacon target ceiling (~2^232; byte[2]=1).
pub const GENESIS_MAX_TARGET_CPU: [u8; 32] = [
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// ASIC worker-safe initial beacon target ceiling (~2^212; byte[5]=0x10).
pub const GENESIS_MAX_TARGET_ASIC: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// `testnet_stress()`'s own initial beacon target ceiling (~2^240; byte[1]=1).
///
/// Raised ×256 (Jul 22, 2026, NC-27-adjacent finding) from
/// `GENESIS_MAX_TARGET_CPU` (2^232), which `testnet_stress()` originally
/// shared with `testnet1()`. At today's realistic per-worker hashrates
/// (~150-210 KH/s), the 2^232 ceiling forced `lib_soak_difficulty.sh`'s
/// floor-softening fallback to trigger on essentially every small-worker-
/// count local soak — not a bug (the fallback produces a correct, self-
/// consistent genesis), but the same headroom-pressure pattern devnet_15
/// hit before its own ×16 relaxation. Given its own dedicated constant
/// (rather than reusing `GENESIS_MAX_TARGET_CPU`) so `testnet1()`/`mainnet()`
/// are unaffected — deliberately not touched, unlike this preset's own
/// data-directory-and-config-only local soak copy (`config/genesis_testnet_stress.toml`,
/// updated to match, per `genesis_toml_file_matches_rust_preset`).
pub const GENESIS_MAX_TARGET_TESTNET_STRESS: [u8; 32] = [
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn default_max_target() -> [u8; 32] {
    GENESIS_MAX_TARGET_CPU
}

fn default_asserted_s_bits() -> u32 { 2 }

fn default_minimum_difficulty() -> u64 { GENESIS_DEFAULT_DIFFICULTY }

fn default_tree_depth() -> u32 { 2 }

impl BeaconGenesisConfig {
    /// Create mainnet genesis configuration
    ///
    /// Worker target ceiling ~2^212 (ASIC-safe). Genesis difficulty D=64 (`bits=0x03000040`).
    ///
    /// (Jul 19, 2026 — NC-19, `docs/plan/Correctness_and_Validation_Plan.md`:
    /// an earlier revision left this genesis's `difficulty`/`bits` unbumped
    /// but bumped its `max_target` array ×16 to 2^208 — the two fields had
    /// drifted apart, since only `max_target` was being used as the
    /// (incorrect, copy-verbatim) basis for shard genesis derivation at the
    /// time. Both fields are now consistent again at the genuine intended
    /// beacon genesis floor: `ShardGenesisConfig::from_beacon_genesis` now
    /// does the real `× SHARD_CALIBRATION_CONSTANT` (16) widening itself, in
    /// target space, off whichever `bits` a beacon genesis actually declares
    /// — no artificial headroom needs to be pre-baked into beacon's own
    /// floor for that to work.)
    /// Expected hashes at D=64, s=2: T_eff=(2^212/64)×4=2^208 → ~2^48.
    /// Beacon block time: 600s, Shard block time: 37.5s
    pub fn mainnet() -> Self {
        Self {
            network_id: NetworkId::Mainnet,
            version: 1,
            timestamp: 1704067200, // 2024-01-01 00:00:00 UTC
            difficulty: GENESIS_DEFAULT_DIFFICULTY,
            bits: GENESIS_DEFAULT_BITS,
            bitcoin_anchor_hash: NetworkId::Mainnet.bitcoin_anchor_hash(),
            bitcoin_anchor_height: NetworkId::Mainnet.bitcoin_anchor_height(),
            bitcoin_anchor_timestamp: 1704067200,
            premine: vec![
                PremineOutput {
                    address: "bc1q...".to_string(),
                    amount: 2_100_000_000_000_000, // 21 000 000 coins × 10^8 atoms/coin
                    description: Some("21M coin premine".to_string()),
                },
            ],
            credit_premine_to_shard_genesis: false,
            genesis_message: "The Times 01/Jan/2024 Shisha Network Launch".to_string(),
            expected_hash: None,
            nonce: None,
            merkle_root: None,
            max_target: GENESIS_MAX_TARGET_ASIC,
            asserted_s_bits: 2,
            minimum_difficulty: GENESIS_DEFAULT_DIFFICULTY,
            shard_expansion: ExpandVotingConfig {
                // Universal lag (2026-07-31): 4 beacon blocks = 40 min grace
                // window at mainnet's 600s pacing. See
                // docs/plan/Epoch_Alignment_Reference.md §6.
                activation_delay: 4,
                ..ExpandVotingConfig::default()
            },
            k_voting: KVotingConfig::default(),
            tree_depth: 2, // matches asserted_s_bits / initial_s_bits (=2); 4 leaves for 3 shards
            shard_calibration: 16,
        }
    }

    /// Create testnet1 genesis configuration
    ///
    /// Worker target ceiling ~2^232 (CPU-safe). Genesis difficulty D=64.
    ///
    /// (Jul 19, 2026 — NC-19: see `mainnet()`'s doc comment above for why
    /// this is no longer artificially widened ×16. Shard genesis derivation
    /// now does that widening itself, on-the-fly, in
    /// `ShardGenesisConfig::from_beacon_genesis`.)
    /// Expected hashes at D=64, s=2: T_eff=(2^232/64)×4=2^228 → ~2^28.
    /// Beacon block time: 600s, Shard block time: 37.5s
    pub fn testnet1() -> Self {
        Self {
            network_id: NetworkId::Testnet1,
            version: 1,
            timestamp: 1704067200,
            difficulty: GENESIS_DEFAULT_DIFFICULTY,
            bits: GENESIS_DEFAULT_BITS,
            bitcoin_anchor_hash: NetworkId::Testnet1.bitcoin_anchor_hash(),
            bitcoin_anchor_height: NetworkId::Testnet1.bitcoin_anchor_height(),
            bitcoin_anchor_timestamp: 1704067200,
            premine: vec![
                PremineOutput {
                    address: "test1q...".to_string(),
                    amount: 10_000_000_000,
                    description: Some("Testnet faucet".to_string()),
                },
            ],
            credit_premine_to_shard_genesis: false,
            genesis_message: "Shisha Network Testnet 1".to_string(),
            expected_hash: None,
            nonce: None,
            merkle_root: None,
            max_target: GENESIS_MAX_TARGET_CPU,
            asserted_s_bits: 2,
            minimum_difficulty: GENESIS_DEFAULT_DIFFICULTY,
            shard_expansion: ExpandVotingConfig {
                // Universal lag (2026-07-31): testnet1 — standard-network grace window (4 beacon blocks = 40 min at 600s pacing).
                // See docs/plan/Epoch_Alignment_Reference.md §6.
                activation_delay: 4,
                ..ExpandVotingConfig::default()
            },
            k_voting: KVotingConfig::default(),
            tree_depth: 2, // matches asserted_s_bits / initial_s_bits (=2)
            shard_calibration: 16,
        }
    }

    /// Create testnet2 genesis configuration
    ///
    /// Worker target ceiling ~2^212 (ASIC-safe). Genesis difficulty D=64 — same floor as `mainnet()`.
    ///
    /// (Jul 19, 2026 — NC-19: see `mainnet()`'s doc comment above for why
    /// this is no longer artificially widened ×16. Shard genesis derivation
    /// now does that widening itself, on-the-fly, in
    /// `ShardGenesisConfig::from_beacon_genesis`.)
    /// Expected hashes at D=64, s=2: T_eff=(2^212/64)×4=2^208 → ~2^48.
    /// Beacon block time: 600s, Shard block time: 37.5s
    pub fn testnet2() -> Self {
        Self {
            network_id: NetworkId::Testnet2,
            version: 1,
            timestamp: 1704067200,
            difficulty: GENESIS_DEFAULT_DIFFICULTY,
            bits: GENESIS_DEFAULT_BITS,
            bitcoin_anchor_hash: NetworkId::Testnet2.bitcoin_anchor_hash(),
            bitcoin_anchor_height: NetworkId::Testnet2.bitcoin_anchor_height(),
            bitcoin_anchor_timestamp: 1704067200,
            premine: vec![
                PremineOutput {
                    address: "test2q...".to_string(),
                    amount: 10_000_000_000,
                    description: Some("Testnet2 faucet".to_string()),
                },
            ],
            credit_premine_to_shard_genesis: false,
            genesis_message: "Shisha Network Testnet 2".to_string(),
            expected_hash: None,
            nonce: None,
            merkle_root: None,
            max_target: GENESIS_MAX_TARGET_ASIC,
            asserted_s_bits: 2,
            minimum_difficulty: GENESIS_DEFAULT_DIFFICULTY,
            shard_expansion: ExpandVotingConfig {
                // Universal lag (2026-07-31): testnet2 — standard-network grace window (4 beacon blocks = 40 min at 600s pacing).
                // See docs/plan/Epoch_Alignment_Reference.md §6.
                activation_delay: 4,
                ..ExpandVotingConfig::default()
            },
            k_voting: KVotingConfig::default(),
            tree_depth: 2, // matches asserted_s_bits / initial_s_bits (=2)
            shard_calibration: 16,
        }
    }

    /// Create devnet genesis configuration
    ///
    /// Worker target ceiling ~2^232 (CPU-safe). Genesis difficulty D=64.
    ///
    /// (Jul 19, 2026 — NC-19: see `mainnet()`'s doc comment above for why
    /// this is no longer artificially widened ×16. Shard genesis derivation
    /// now does that widening itself, on-the-fly, in
    /// `ShardGenesisConfig::from_beacon_genesis`.
    ///
    /// **NC-19 difficulty flooring/ceiling (Q2, Jul 20):** Phase A (Jul 21)
    /// sets D=64 as the beacon floor with `max_target` as the worker ceiling;
    /// see `docs/plan/Genesis_Config_Defaults_Plan.md`.)
    /// Expected hashes at D=64, s=2: T_eff=(2^232/64)×4=2^228 → ~2^28.
    /// Beacon block time: 150s, Shard block time: 9.375s
    pub fn devnet() -> Self {
        Self {
            network_id: NetworkId::Devnet,
            version: 1,
            timestamp: 1704067200,
            difficulty: GENESIS_DEFAULT_DIFFICULTY,
            bits: GENESIS_DEFAULT_BITS,
            bitcoin_anchor_hash: NetworkId::Devnet.bitcoin_anchor_hash(),
            bitcoin_anchor_height: NetworkId::Devnet.bitcoin_anchor_height(),
            bitcoin_anchor_timestamp: 1704067200,
            premine: vec![],
            credit_premine_to_shard_genesis: false,
            genesis_message: "Shisha Network Devnet".to_string(),
            expected_hash: None,
            nonce: None,
            merkle_root: None,
            max_target: GENESIS_MAX_TARGET_CPU,
            asserted_s_bits: 2,
            minimum_difficulty: GENESIS_DEFAULT_DIFFICULTY,
            shard_expansion: ExpandVotingConfig {
                // Universal lag (2026-07-31): devnet — soak/fast-network minimal grace window (1 beacon block).
                // See docs/plan/Epoch_Alignment_Reference.md §6.
                activation_delay: 1,
                ..ExpandVotingConfig::default()
            },
            k_voting: KVotingConfig::default(),
            tree_depth: 2, // matches asserted_s_bits / initial_s_bits (=2)
            shard_calibration: 16,
        }
    }

    /// Create testnet-stress genesis configuration.
    ///
    /// See `docs/plan/Testnet_Stress_Launch_Plan.md` §3. Dedicated 30-day-cap
    /// stress/load-test network — not for production use, and not intended
    /// to be long-lived like testnet1/testnet2.
    ///
    /// Initial beacon target = ~2^232 CPU ceiling (same class as devnet/testnet1).
    /// `shard_expansion.epoch_length = 256` (TS-2b) instead of the default 4096,
    /// so shard-count ramp can complete inside the 30-day window.
    ///
    /// Stress launch uses the same **3 shards / s=2** genesis as standard
    /// presets (fills capacity; in optimal band). Faster expand ramp via
    /// `step_denominator = 2` and `epoch_length = 256` (TS-2b).
    ///
    /// ⚠️ **Placeholder genesis** — `timestamp`/`bitcoin_anchor_timestamp` and
    /// the Bitcoin anchor (`bitcoin_anchors::TESTNET_STRESS_ANCHOR_HASH/HEIGHT`,
    /// currently aliased to the devnet anchor) must be regenerated with a real,
    /// recent Bitcoin block at actual launch time (T0), the same way `premine`
    /// addresses need real keys before funds are spendable. This mirrors the
    /// existing `MAINNET_ANCHOR_HASH = [0u8; 32]` placeholder in this file.
    pub fn testnet_stress() -> Self {
        Self {
            network_id: NetworkId::TestnetStress,
            version: 1,
            // Real, fixed launch timestamp — anchored to Bitcoin block 964050's
            // own timestamp (see bitcoin_anchors::TESTNET_STRESS_ANCHOR_HASH/HEIGHT
            // above). No longer regenerated on every soak run.
            timestamp: 1787689496,
            difficulty: GENESIS_DEFAULT_DIFFICULTY,
            bits: 0x0300_0040, // u128_to_rbits(64); beacon floor for s=2 × cal=16
            bitcoin_anchor_hash: NetworkId::TestnetStress.bitcoin_anchor_hash(),
            bitcoin_anchor_height: NetworkId::TestnetStress.bitcoin_anchor_height(),
            bitcoin_anchor_timestamp: 1787689496,
            premine: vec![
                PremineOutput {
                    // Real, spendable x-only Schnorr pubkey — TS-FAUCET's own
                    // keypair (private key lives only in faucet-server's runtime
                    // config, never in this repo). Every other premine entry
                    // below is still a human label with no matching key.
                    address: "0xd5c98a0cd803f46579317eeda18c965d225959f9c4e6d027b82725e7fa95cd0f".to_string(),
                    amount: 100_000_000_000_000, // 1 000 000 coins
                    description: Some("Semipublic faucet drip wallet (TS-FAUCET)".to_string()),
                },
                PremineOutput {
                    address: "teststress1-producer-a-treasury".to_string(),
                    amount: 50_000_000_000_000, // 500 000 coins
                    description: Some("Block producer A coinbase funding / contract".to_string()),
                },
                PremineOutput {
                    address: "teststress1-producer-b-treasury".to_string(),
                    amount: 25_000_000_000_000, // 250 000 coins
                    description: Some("Block producer B coinbase funding / contract (2:1 hash ratio)".to_string()),
                },
                // SPAM-V2 Phase 2: 8 real, DISTINCT keypairs (not human
                // labels; MUST be distinct -- validate_premine rejects
                // duplicate addresses) -- see the matching block in
                // config/genesis_testnet_stress.toml for the full rationale.
                // Private halves: config/tx_spammer_age_aware_secret_keys.hex
                // (gitignored, not committed), one line per entry in order.
                PremineOutput {
                    address: "0x0dc31d5ee594bd2cc3d99fc27065d986edf574fcf8d16d8ba2955ce50d2b47d2".to_string(),
                    amount: 5_000_000_000_000, // 50 000 coins
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #0".to_string()),
                },
                PremineOutput {
                    address: "0x5beebbf8c70cd026ee2730511e98514870e78e59ad36b7844c06c220a08a4882".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #1".to_string()),
                },
                PremineOutput {
                    address: "0x809a55c2a4cc37497f86d7174dd29cc04ab44bc7578d887ca666eb9998e28563".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #2".to_string()),
                },
                PremineOutput {
                    address: "0x97e3ea6ab9e673f66e92656b7f3a4de00c45a6d464468c37ed07cacacc68f16a".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #3".to_string()),
                },
                PremineOutput {
                    address: "0x740595e7f8c275a516631134698fed3bd288b17d386d5aa9802605915bde5d9e".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #4".to_string()),
                },
                PremineOutput {
                    address: "0x76f26eb10684ace464fc39b74030267e6f322980d6645073af9788c51ebf113a".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #5".to_string()),
                },
                PremineOutput {
                    address: "0x4b91a5253bd70d2459cc271ba768662cafc14059ced18efb6cad6b2cd981fdf1".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #6".to_string()),
                },
                PremineOutput {
                    address: "0x95208050262701824f919a94ca509d130b1f3a13ad349ea638004d50bcc57072".to_string(),
                    amount: 5_000_000_000_000,
                    description: Some("Spam UTXO starting point (TS-T-10 unsigned / SPAM-V2 Phase 2 signed) #7".to_string()),
                },
                PremineOutput {
                    address: "teststress1-filament-demo".to_string(),
                    amount: 10_000_000_000_000, // 100 000 coins
                    description: Some("Filament side-task payment URI demo wallet".to_string()),
                },
            ],
            // Only preset that credits premine onto shard genesis too — see
            // TS-FAUCET / TS-T-10; designed before NC-36 added a beacon-chain
            // mempool, so premine-funded testnet-stress tooling spends via a
            // shard instead (never revisited to use the beacon mempool path).
            credit_premine_to_shard_genesis: true,
            // ASCII hyphen, as in config/genesis_testnet_stress.toml: the
            // message is hashed into the genesis coinbase, and `expected_hash`
            // below was mined with this exact text (an em-dash here gave a
            // different genesis block — VF-9 / TEST-COV-1).
            genesis_message: "Shisha Network Testnet-Stress - 30-day stress launch".to_string(),
            // Mined Aug 26, 2026 via `cargo run --release --bin genesis_miner --
            // --network testnet_stress` after fixing that tool's stale
            // nbits_to_target target derivation (see genesis_miner.rs's own
            // comment). Must stay in sync with config/genesis_testnet_stress.toml
            // (checked by genesis_toml_file_matches_rust_preset).
            expected_hash: Some([
                0x00, 0x00, 0x06, 0x22, 0xf9, 0x8d, 0x6d, 0x05,
                0x82, 0x57, 0x8e, 0x85, 0x53, 0x45, 0xd3, 0x9a,
                0xf3, 0xa8, 0xfe, 0x96, 0x68, 0x46, 0xac, 0x3f,
                0xa4, 0xdd, 0xbc, 0x31, 0x03, 0x00, 0x00, 0x40,
            ]),
            nonce: Some(1123560),
            merkle_root: None,
            max_target: GENESIS_MAX_TARGET_TESTNET_STRESS,
            asserted_s_bits: 2,
            // Beacon floor for s=2 × cal=16 is 64 — DAA must not retarget below it.
            minimum_difficulty: GENESIS_DEFAULT_DIFFICULTY,
            shard_expansion: ExpandVotingConfig {
                initial_shard_count: 3,
                initial_s_bits: 2,
                threshold_numerator: 5,
                threshold_denominator: 8,
                step_numerator: 1,
                step_denominator: 2, // ~50%/epoch when count≥4 (faster than default /4)
                // Universal lag (2026-07-31): soak/fast-network minimal grace
                // window (1 beacon block) — see Epoch_Alignment_Reference.md §6.
                // Was `SHARD_ACTIVATION_DELAY` (16), the pre-fix generic default.
                activation_delay: 1,
                epoch_length: 256, // TS-2b — required for fast ramp inside 30 days
            },
            // Epoch alignment fix (2026-07-31): `activation_height`'s default (4096)
            // means "first governance epoch" only when `epoch_length` is also 4096.
            // With `epoch_length = 256` above, an unchanged default would make
            // k-voting inert for 16 governance epochs instead of 1. Override to
            // match this network's real epoch length — see
            // `docs/plan/Epoch_Alignment_Reference.md` §4.
            k_voting: KVotingConfig {
                activation_height: 256,
                // CPU testnet: k = 2^16 so near-floor shard blocks (~1 atom at
                // k=1) pay ~65 536 atoms — enough for TX-12 fees at 16 atoms /
                // 4 bytes. Voting still only declines from this ceiling.
                k_initial_kbits: crate::common::crypto::k_bits::K_TIMES_2_POW_16_KBITS,
                ..KVotingConfig::default()
            },
            // Deliberately **larger** than initial s=2: standard nets set
            // tree_depth == s, but stress needs 16 MM leaves for the §9
            // expand ramp (3 → 7 → 15) while hash-sorting starts at s=2.
            // Operator `[mining_pool].merkle_tree_depth` must match this 4.
            tree_depth: 4,
            shard_calibration: 16,
        }
    }

    /// Calculate total premine amount
    pub fn total_premine(&self) -> u64 {
        self.premine.iter().map(|p| p.amount).sum()
    }
    
    /// Validate premine configuration
    pub fn validate_premine(&self) -> Result<(), String> {
        use crate::common::emission_schedule::PREMINE_ATOMS;

        // Check for duplicate addresses
        let mut addresses = std::collections::HashSet::new();
        for output in &self.premine {
            if !addresses.insert(&output.address) {
                return Err(format!("Duplicate premine address: {}", output.address));
            }
        }

        // Total must not exceed the canonical premine (21 000 000 coins).
        let total = self.total_premine();
        if total > PREMINE_ATOMS {
            return Err(format!(
                "Total premine {} atoms exceeds canonical maximum {} atoms ({} coins)",
                total,
                PREMINE_ATOMS,
                PREMINE_ATOMS / 100_000_000,
            ));
        }

        Ok(())
    }

    /// G-6 / CV-64: `bits` (compact **rBits**), `max_target`, and `asserted_s_bits`
    /// must be internally consistent.
    ///
    /// After the header-rBits cutover (Jul 20, 2026):
    /// - `bits` = `u128_to_rbits(difficulty)` (compact difficulty, not nBits target)
    /// - PoW hardness comes from `max_target` (worker ceiling) and `difficulty` (start stamp)
    ///   via `rbits_to_target(bits, max_target, asserted_s)`
    ///
    /// Phase A (Jul 21, 2026) enforces genesis D floors: `D ≥ 2^s` (any chain) and
    /// `D ≥ shard_calibration × 2^s` (beacon). See `Genesis_Config_Defaults_Plan.md`.
    ///
    /// `asserted_s_bits` is the genesis-frozen difficulty-scaling exponent
    /// folded into PoW expand. Distinct from live true s after expansion epochs,
    /// but at height 0 the two must agree (Header rBits §5.7).
    pub fn validate_difficulty_params(&self) -> Result<(), String> {
        use crate::common::crypto::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};
        use crate::common::expand_voting::{compute_required_s_bits, s_bits_for_chain_count};

        let expected_rbits = u128_to_rbits(self.difficulty as u128);
        if self.bits != expected_rbits {
            return Err(format!(
                "genesis bits 0x{:08x} inconsistent with difficulty {} \
                 (expected rBits 0x{:08x} = u128_to_rbits(difficulty))",
                self.bits, self.difficulty, expected_rbits
            ));
        }
        if rbits_to_u128_approx(self.bits) == 0 && self.difficulty != 0 {
            return Err(format!(
                "genesis bits 0x{:08x} decodes to zero weight but difficulty={}",
                self.bits, self.difficulty
            ));
        }
        if self.max_target == [0u8; 32] {
            return Err("max_target (initial beacon target) must be non-zero".to_string());
        }

        if self.asserted_s_bits == 0 {
            return Err("asserted_s_bits must be > 0 (hash-sorting requires at least one bit)".to_string());
        }
        if self.asserted_s_bits > 15 {
            return Err(format!(
                "asserted_s_bits ({}) exceeds protocol maximum 15",
                self.asserted_s_bits
            ));
        }

        // Height-0 consistency (Jul 20, 2026): genesis asserted_s_bits must match
        // expand's initial_s_bits, and that width must cover initial_shard_count
        // under the count→s capacity rule (`s_bits_for_chain_count` /
        // `compute_required_s_bits`). Headroom above the absolute minimum is
        // allowed (e.g. count=4 → min s=3, genesis may freeze s=4).
        self.shard_expansion.validate()?;
        let initial_s = self.shard_expansion.initial_s_bits;
        let initial_count = self.shard_expansion.initial_shard_count;
        if self.asserted_s_bits != initial_s as u32 {
            return Err(format!(
                "asserted_s_bits ({}) must equal shard_expansion.initial_s_bits ({}) at genesis / height 0",
                self.asserted_s_bits, initial_s
            ));
        }
        let min_s = s_bits_for_chain_count(initial_count);
        if compute_required_s_bits(initial_count, initial_s) != initial_s {
            return Err(format!(
                "genesis s_bits ({}) does not cover initial_shard_count ({}); \
                 minimum under count→s mapping is {} (capacity 2^s − 1)",
                initial_s, initial_count, min_s
            ));
        }

        if shard_calibration_shift_bits(self.shard_calibration).is_none() {
            return Err(format!(
                "shard_calibration must be a power of two ≥ 1 (got {})",
                self.shard_calibration
            ));
        }

        let d = self.difficulty as u128;
        let s = self.asserted_s_bits;
        let any_chain_floor = beacon_any_chain_floor_u128(s)
            .ok_or_else(|| format!("2^asserted_s_bits overflow (s={s})"))?;
        if d < any_chain_floor {
            return Err(format!(
                "genesis difficulty {} below any-chain floor 2^asserted_s_bits = {} \
                 (D must be ≥ 2^s)",
                self.difficulty, any_chain_floor
            ));
        }
        let beacon_floor = beacon_difficulty_floor_u128(self.shard_calibration, s)
            .ok_or_else(|| "beacon difficulty floor overflow".to_string())?;
        if d < beacon_floor {
            return Err(format!(
                "genesis difficulty {} below beacon floor shard_calibration×2^s = {} \
                 (cal={}, s={})",
                self.difficulty, beacon_floor, self.shard_calibration, s
            ));
        }

        if (self.minimum_difficulty as u128) < beacon_floor {
            return Err(format!(
                "minimum_difficulty {} below beacon floor shard_calibration×2^s = {} \
                 (cal={}, s={}); DAA must not retarget below the PoW floor",
                self.minimum_difficulty, beacon_floor, self.shard_calibration, s
            ));
        }
        if self.difficulty < self.minimum_difficulty {
            return Err(format!(
                "genesis difficulty {} below minimum_difficulty {}",
                self.difficulty, self.minimum_difficulty
            ));
        }

        // Soft warn for under-filled (s, count) is emitted inside
        // `shard_expansion.validate()` via `emit_nonoptimal_s_bits_warning`
        // (already called above). Standard + stress presets (3/s=2) are
        // in-band; the legacy under-filled tuple (4/s=4) still soft-warns
        // when used as a fixture (`ExpandVotingConfig` tests).

        Ok(())
    }

    /// Ensure `shard_calibration == beacon_interval / shard_interval` using
    /// integer arithmetic only:
    /// `beacon_secs × shard_den / shard_num == shard_calibration`
    /// (and the division is exact). Call after DAA / `init_block_intervals`.
    pub fn validate_shard_calibration_vs_intervals(
        &self,
        beacon_secs: u64,
        shard_interval_num: u64,
        shard_interval_den: u64,
    ) -> Result<(), String> {
        let den = shard_interval_den.max(1);
        let num = shard_interval_num.max(1);
        let product = (beacon_secs as u128)
            .checked_mul(den as u128)
            .ok_or_else(|| "beacon×shard_den overflow computing calibration".to_string())?;
        if product % (num as u128) != 0 {
            return Err(format!(
                "shard_calibration {}: beacon_interval {}s / shard_interval {}/{}s is not an integer ratio",
                self.shard_calibration, beacon_secs, num, den
            ));
        }
        let expected = product / (num as u128);
        if expected > u32::MAX as u128 || expected as u32 != self.shard_calibration {
            return Err(format!(
                "shard_calibration {} != beacon/shard interval ratio {} ({}s × {} / {}) — \
                 intervals and genesis calibration must stay in lockstep (NC-19)",
                self.shard_calibration, expected, beacon_secs, den, num
            ));
        }
        Ok(())
    }

    /// Compare consensus-critical fields against the Rust network preset.
    pub fn validate_matches_preset(&self) -> Result<(), String> {
        let preset = match self.network_id {
            NetworkId::Mainnet => Self::mainnet(),
            NetworkId::Testnet1 => Self::testnet1(),
            NetworkId::Testnet2 => Self::testnet2(),
            NetworkId::Devnet => Self::devnet(),
            NetworkId::TestnetStress => Self::testnet_stress(),
            NetworkId::Custom => return Ok(()),
        };

        if self.bits != preset.bits {
            return Err(format!(
                "bits 0x{:08x} differs from {:?} preset 0x{:08x}",
                self.bits, self.network_id, preset.bits
            ));
        }
        if self.max_target != preset.max_target {
            return Err(format!(
                "max_target differs from {:?} preset",
                self.network_id
            ));
        }
        if self.asserted_s_bits != preset.asserted_s_bits {
            return Err(format!(
                "asserted_s_bits {} differs from {:?} preset {}",
                self.asserted_s_bits, self.network_id, preset.asserted_s_bits
            ));
        }
        if self.minimum_difficulty != preset.minimum_difficulty {
            return Err(format!(
                "minimum_difficulty {} differs from {:?} preset {}",
                self.minimum_difficulty, self.network_id, preset.minimum_difficulty
            ));
        }
        if self.shard_calibration != preset.shard_calibration {
            return Err(format!(
                "shard_calibration {} differs from {:?} preset {}",
                self.shard_calibration, self.network_id, preset.shard_calibration
            ));
        }
        // Epoch alignment fix (2026-07-31): activation_height must track
        // shard_expansion.epoch_length per-network (see
        // docs/plan/Epoch_Alignment_Reference.md §4) — a TOML file with no
        // `[beacon.k_voting]` section silently deserializes to the global
        // default (4096) via KVotingConfig's `#[serde(default)]`, which would
        // diverge from a preset that overrides it (as testnet_stress() now
        // does) with no other check catching the drift.
        if self.k_voting.activation_height != preset.k_voting.activation_height {
            return Err(format!(
                "k_voting.activation_height {} differs from {:?} preset {}",
                self.k_voting.activation_height, self.network_id, preset.k_voting.activation_height
            ));
        }
        if self.k_voting.k_initial_kbits != preset.k_voting.k_initial_kbits {
            return Err(format!(
                "k_voting.k_initial_kbits 0x{:08x} differs from {:?} preset 0x{:08x}",
                self.k_voting.k_initial_kbits,
                self.network_id,
                preset.k_voting.k_initial_kbits
            ));
        }

        Ok(())
    }
}

/// Shard genesis block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardGenesisConfig {
    /// Network identifier (must match beacon network)
    pub network_id: NetworkId,

    /// Shard ID (0-255)
    pub shard_id: u16,

    /// Genesis block version
    pub version: u32,

    /// Genesis block timestamp
    pub timestamp: u64,

    /// Bitcoin anchor timestamp used as the epoch for delta calculations (same as beacon)
    pub bitcoin_anchor_timestamp: u64,

    /// Initial difficulty for this shard (legacy u64; prefer `bits` rBits)
    pub difficulty: u64,

    /// Initial compact **rBits** (header work field). Was nBits pre–header-rBits.
    pub bits: u32,

    /// Worker-safe target ceiling (legacy name matches beacon `max_target`).
    /// Used by `rbits_to_target` for Strategy A PoW. Copied from the beacon
    /// genesis when constructing via [`Self::from_beacon_genesis`].
    #[serde(default = "default_max_target")]
    pub max_target: [u8; 32],

    /// Beacon block hash that authorizes this shard's creation
    pub beacon_anchor_hash: [u8; 32],

    /// Beacon block height of the anchor
    pub beacon_anchor_height: u32,

    /// Initial merge mining weight for this shard
    pub initial_merge_weight: u64,

    /// Expected genesis block hash (for validation)
    pub expected_hash: Option<[u8; 32]>,

    /// Number of SHARD blocks a coinbase output must age before it can be spent (TX-8).
    ///
    /// **Derived, not a per-network constant** (NC-91, Aug 27 2026; `docs/plan/Coinbase_Maturity_Design.md`):
    /// `from_beacon_anchor_block` sets it to `shard_coinbase_maturity(epoch_length, shard_calibration)`,
    /// i.e. `max(1, epoch_length / 256) * 4 * shard_calibration` (mainnet-class: 64 beacon blocks = 1024
    /// shard blocks, the same wall-clock wait). The flat value `from_beacon_anchor` writes first
    /// (100 on mainnet/testnets, 0 elsewhere) is only a placeholder that the derivation overwrites; no
    /// production path reads it unreplaced. `0` still disables the check (tests, bench clones).
    pub coinbase_maturity: u32,

    /// TS-FAUCET / TS-T-10: extra coinbase outputs credited on this shard's
    /// very first mined block only (empty for every preset except
    /// testnet-stress, via `BeaconGenesisConfig::credit_premine_to_shard_genesis`).
    /// See that field's doc comment for why this exists — shards otherwise
    /// never receive any premine.
    #[serde(default)]
    pub premine: Vec<PremineOutput>,
}

impl ShardGenesisConfig {
    /// Total of `premine` (0 when empty, the common case).
    pub fn total_premine(&self) -> u64 {
        self.premine.iter().map(|p| p.amount).sum()
    }

    /// Builder: attach premine outputs to be credited on this shard's first
    /// mined block (TS-FAUCET / TS-T-10). No-op (empty vec) leaves existing
    /// behavior unchanged.
    pub fn with_premine(mut self, premine: Vec<PremineOutput>) -> Self {
        self.premine = premine;
        self
    }
    /// Create shard genesis configuration from beacon anchor
    pub fn from_beacon_anchor(
        network_id: NetworkId,
        shard_id: u16,
        beacon_anchor_hash: [u8; 32],
        beacon_anchor_height: u32,
        timestamp: u64,
        bitcoin_anchor_timestamp: u64,
        initial_difficulty: u64,
        initial_bits: u32,
        initial_merge_weight: u64,
        initial_target: [u8; 32],
    ) -> Self {
        // Placeholder only: `from_beacon_anchor_block` overwrites this with the epoch-derived value
        // (`shard_coinbase_maturity`). Do not rely on these flat numbers.
        let coinbase_maturity = match network_id {
            NetworkId::Mainnet | NetworkId::Testnet1 | NetworkId::Testnet2 => 100,
            // Testnet-stress uses devnet-class block intervals (plan §3.1) —
            // immediate coinbase spending, same as devnet/custom.
            NetworkId::Devnet | NetworkId::TestnetStress | NetworkId::Custom => 0,
        };
        Self {
            network_id,
            shard_id,
            version: 1,
            timestamp,
            bitcoin_anchor_timestamp,
            difficulty: initial_difficulty,
            bits: initial_bits,
            max_target: initial_target,
            beacon_anchor_hash,
            beacon_anchor_height,
            initial_merge_weight,
            expected_hash: None,
            coinbase_maturity,
            premine: Vec::new(),
        }
    }

    /// Create a shard genesis from the network's loaded beacon genesis.
    ///
    /// Derives `bits` as `beacon.bits`'s target widened by
    /// `beacon.shard_calibration` (default `16`) — the fixed beacon:shard
    /// block-interval ratio — so a shard genesis is exactly as much easier
    /// than the beacon anchor as the intended shard block cadence requires.
    /// See [`Self::bits_from_beacon_nbits`].
    ///
    /// **NC-19:** for genesis-preprovisioned shards (activation height 0)
    /// the beacon genesis *is* the anchor block, so this is correct. For
    /// dynamically-activated shards, prefer
    /// [`Self::from_beacon_anchor_block`] / live `activate_shard` with the
    /// real beacon block's `bits` at the anchor height.
    pub fn from_beacon_genesis(beacon: &BeaconGenesisConfig, shard_id: u16) -> Self {
        Self::from_beacon_anchor_block(
            beacon,
            shard_id,
            beacon.bitcoin_anchor_hash,
            0,
            beacon.timestamp,
            beacon.bits,
        )
    }

    /// Derive shard genesis from a live beacon **block** at the shard's
    /// activation / anchor height (NC-19 Jul 20 decision).
    ///
    /// `beacon_bits` is the anchor block's own nBits (possibly DAA-adjusted),
    /// not the static genesis-config field. Widens by `beacon.shard_calibration`
    /// in target space.
    pub fn from_beacon_anchor_block(
        beacon: &BeaconGenesisConfig,
        shard_id: u16,
        beacon_anchor_hash: [u8; 32],
        beacon_anchor_height: u32,
        timestamp: u64,
        beacon_bits: u32,
    ) -> Self {
        let shard_bits = Self::bits_from_beacon_nbits(beacon_bits, beacon.shard_calibration);
        let mut config = Self::from_beacon_anchor(
            beacon.network_id,
            shard_id,
            beacon_anchor_hash,
            beacon_anchor_height,
            timestamp,
            beacon.bitcoin_anchor_timestamp,
            1, // genesis difficulty is always 1, relative to `shard_bits`
            shard_bits,
            1000,
            beacon.max_target,
        );
        // NC-91 (Aug 27, 2026): derive from the network's real epoch length
        // instead of `from_beacon_anchor`'s own flat per-network-class
        // fallback (mainnet-class=100 / everything-else=0) — see
        // `shard_coinbase_maturity`'s own doc comment for why.
        config.coinbase_maturity = crate::common::validation::shard_coinbase_maturity(
            beacon.shard_expansion.epoch_length,
            beacon.shard_calibration,
        );
        config
    }

    /// Derive shard genesis compact **rBits** from beacon rBits, softening by
    /// `shard_calibration` in difficulty space: `D_shard = max(1, D_beacon / cal)`.
    ///
    /// When beacon is already at difficulty 1, calibration saturates (same class
    /// as the old target-space ceiling when beacon work was already maximal).
    pub fn bits_from_beacon_nbits(beacon_rbits: u32, shard_calibration: u32) -> u32 {
        use crate::common::crypto::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};

        let d_beacon = rbits_to_u128_approx(beacon_rbits).max(1);
        let cal = (shard_calibration.max(1)) as u128;
        let d_shard = (d_beacon / cal).max(1);
        u128_to_rbits(d_shard)
    }

    /// Create a devnet shard genesis configuration for the given shard ID.
    ///
    /// Uses the devnet beacon configuration's bitcoin_anchor_hash as the
    /// beacon_anchor_hash, mirroring the devnet constant previously hardcoded
    /// in `ShardChain` as `BITCOIN_ANCHOR_HASH`.  Intended for test code and
    /// fixtures that have no `NetworkGenesisConfig`. Production
    /// `start_shard_nodes` must use [`Self::from_beacon_genesis`] (or an
    /// explicit `[shards]` map entry) instead.
    pub fn devnet(shard_id: u16) -> Self {
        Self::from_beacon_genesis(&BeaconGenesisConfig::devnet(), shard_id)
    }

    /// Validate shard genesis configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.shard_id >= 256 {
            return Err(format!("Invalid shard ID: {}", self.shard_id));
        }
        
        // Shard genesis must have valid beacon anchor (not all zeros)
        if self.beacon_anchor_hash == [0u8; 32] {
            return Err("Shard genesis must have valid beacon anchor hash".to_string());
        }
        
        if self.timestamp == 0 {
            return Err("Shard genesis must have valid timestamp".to_string());
        }
        
        Ok(())
    }
}

/// Complete network genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGenesisConfig {
    /// Beacon chain genesis
    pub beacon: BeaconGenesisConfig,
    
    /// Initial shard genesis configurations
    pub shards: HashMap<u16, ShardGenesisConfig>,
    
    /// P2P framing magic for this network, as wire bytes.
    ///
    /// **Informational / documentation mirror.** The running node takes its
    /// framing magic from the P2P config's `network` name via
    /// [`super::network_identity::p2p_network_magic`] (the single source of
    /// truth — see that module's table), never from this field. Presets fill
    /// it from that same table so a genesis file shows the value its network
    /// actually uses; chain identity itself is the genesis hash exchanged in
    /// the handshake (BV-PROTO-1 VF-7).
    pub network_magic: [u8; 4],
    
    /// Network protocol version
    pub protocol_version: u32,
}

impl NetworkGenesisConfig {
    /// Create mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            beacon: BeaconGenesisConfig::mainnet(),
            shards: HashMap::new(),
            network_magic: super::network_identity::p2p_network_magic_bytes(
                super::network_identity::P2pProtocolKind::ShishaNet, "mainnet"),
            protocol_version: 1,
        }
    }
    
    /// Create testnet1 configuration
    pub fn testnet1() -> Self {
        Self {
            beacon: BeaconGenesisConfig::testnet1(),
            shards: HashMap::new(),
            network_magic: super::network_identity::p2p_network_magic_bytes(
                super::network_identity::P2pProtocolKind::ShishaNet, "testnet1"),
            protocol_version: 1,
        }
    }
    
    /// Create testnet2 configuration
    pub fn testnet2() -> Self {
        Self {
            beacon: BeaconGenesisConfig::testnet2(),
            shards: HashMap::new(),
            network_magic: super::network_identity::p2p_network_magic_bytes(
                super::network_identity::P2pProtocolKind::ShishaNet, "testnet2"),
            protocol_version: 1,
        }
    }
    
    /// Create devnet configuration
    pub fn devnet() -> Self {
        Self {
            beacon: BeaconGenesisConfig::devnet(),
            shards: HashMap::new(),
            network_magic: super::network_identity::p2p_network_magic_bytes(
                super::network_identity::P2pProtocolKind::ShishaNet, "devnet"),
            protocol_version: 1,
        }
    }

    /// Create testnet-stress configuration (§3.1 — dedicated wire isolation
    /// magic, distinct from testnet1/testnet2/mainnet/devnet).
    pub fn testnet_stress() -> Self {
        Self {
            beacon: BeaconGenesisConfig::testnet_stress(),
            shards: HashMap::new(),
            network_magic: super::network_identity::p2p_network_magic_bytes(
                super::network_identity::P2pProtocolKind::ShishaNet, "testnet-stress"),
            protocol_version: 1,
        }
    }

    /// Load configuration from file
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config file: {}", e))
    }
    
    /// Save configuration to file
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write config file: {}", e))
    }
    
    /// Validate entire network configuration
    pub fn validate(&self) -> Result<(), String> {
        self.beacon.validate_premine()?;
        self.beacon.validate_difficulty_params()?;
        self.beacon.validate_matches_preset()?;

        if self.beacon.network_id == NetworkId::Mainnet {
            use crate::common::emission_schedule::PREMINE_ATOMS;
            let total = self.beacon.total_premine();
            if total != PREMINE_ATOMS {
                return Err(format!(
                    "mainnet premine must total exactly {} atoms (21M coins); got {} atoms",
                    PREMINE_ATOMS, total
                ));
            }
        }
        
        for (shard_id, shard_config) in &self.shards {
            if *shard_id != shard_config.shard_id {
                return Err(format!(
                    "Shard ID mismatch: key {} vs config {}",
                    shard_id, shard_config.shard_id
                ));
            }
            
            shard_config.validate()?;

            if shard_config.network_id != self.beacon.network_id {
                return Err(format!(
                    "Shard {} network ID {:?} doesn't match beacon network ID {:?}",
                    shard_id, shard_config.network_id, self.beacon.network_id
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod testnet_stress_tests {
    use super::*;

    #[test]
    fn network_id_as_str_is_hyphenated() {
        assert_eq!(NetworkId::TestnetStress.as_str(), "testnet-stress");
    }

    #[test]
    fn preset_passes_premine_validation() {
        let cfg = BeaconGenesisConfig::testnet_stress();
        cfg.validate_premine().expect("premine must validate");
    }

    #[test]
    fn preset_passes_difficulty_validation() {
        let cfg = BeaconGenesisConfig::testnet_stress();
        cfg.validate_difficulty_params()
            .expect("genesis difficulty params must validate");
    }

    /// Jul 20, 2026 — Header rBits §5.7: at height 0, asserted_s_bits must equal
    /// initial_s_bits and cover initial_shard_count under the count→s mapping.
    #[test]
    fn genesis_asserted_s_must_match_initial_count_mapping() {
        use crate::common::expand_voting::s_bits_for_chain_count;

        for cfg in [
            BeaconGenesisConfig::mainnet(),
            BeaconGenesisConfig::testnet1(),
            BeaconGenesisConfig::testnet2(),
            BeaconGenesisConfig::devnet(),
            BeaconGenesisConfig::testnet_stress(),
        ] {
            cfg.validate_difficulty_params()
                .unwrap_or_else(|e| panic!("{:?} genesis failed asserted_s check: {e}", cfg.network_id));
            assert_eq!(
                cfg.asserted_s_bits,
                cfg.shard_expansion.initial_s_bits as u32,
                "{:?}: asserted_s_bits != initial_s_bits",
                cfg.network_id
            );
            let min_s = s_bits_for_chain_count(cfg.shard_expansion.initial_shard_count);
            assert!(
                cfg.asserted_s_bits >= min_s as u32,
                "{:?}: asserted_s_bits {} < minimum covering s {}",
                cfg.network_id,
                cfg.asserted_s_bits,
                min_s
            );
        }

        // Mismatch: asserted_s_bits ≠ initial_s_bits
        let mut bad = BeaconGenesisConfig::devnet();
        bad.asserted_s_bits = 5;
        let err = bad.validate_difficulty_params().unwrap_err();
        assert!(
            err.contains("asserted_s_bits") && err.contains("initial_s_bits"),
            "expected asserted/initial mismatch error, got: {err}"
        );

        // Insufficient width: s too small for count
        let mut tiny = BeaconGenesisConfig::devnet();
        tiny.asserted_s_bits = 2;
        tiny.shard_expansion.initial_s_bits = 2;
        tiny.shard_expansion.initial_shard_count = 4;
        // capacity at s=2 is 3 → fails shard_expansion.validate
        let err = tiny.validate_difficulty_params().unwrap_err();
        assert!(
            err.contains("initial_shard_count") || err.contains("does not cover"),
            "expected capacity/cover error, got: {err}"
        );
    }

    #[test]
    fn preset_shard_expansion_validates() {
        let cfg = BeaconGenesisConfig::testnet_stress();
        cfg.shard_expansion.validate().expect("shard_expansion must validate");
        assert_eq!(cfg.shard_expansion.epoch_length, 256, "TS-2b");
    }

    /// Phase A soft warn: stress matches standard 3/s=2 (in-band); explicit
    /// (4,4) still soft-warns via the helper. Regression for
    /// `nonoptimal_s_bits_warning`.
    #[test]
    fn stress_soft_warns_standard_presets_do_not() {
        use crate::common::expand_voting::nonoptimal_s_bits_warning;

        let stress = BeaconGenesisConfig::testnet_stress();
        assert_eq!(stress.shard_expansion.initial_shard_count, 3);
        assert_eq!(stress.shard_expansion.initial_s_bits, 2);
        assert!(
            nonoptimal_s_bits_warning(2, 3).is_none(),
            "testnet-stress 3/s=2 must be in-band"
        );
        // Legacy under-filled tuple still warns (helper unit coverage).
        assert!(
            nonoptimal_s_bits_warning(4, 4).is_some(),
            "(s=4, count=4) must soft-warn"
        );
        stress
            .validate_difficulty_params()
            .expect("soft warn must not fail validate_difficulty_params");

        for cfg in [
            BeaconGenesisConfig::mainnet(),
            BeaconGenesisConfig::testnet1(),
            BeaconGenesisConfig::testnet2(),
            BeaconGenesisConfig::devnet(),
            BeaconGenesisConfig::testnet_stress(),
        ] {
            assert!(
                nonoptimal_s_bits_warning(
                    cfg.shard_expansion.initial_s_bits,
                    cfg.shard_expansion.initial_shard_count
                )
                .is_none(),
                "{:?}: expected in-band (s={}, count={})",
                cfg.network_id,
                cfg.shard_expansion.initial_s_bits,
                cfg.shard_expansion.initial_shard_count
            );
        }
    }

    /// Genesis-lock regression (design-doc §7.2): standard presets set
    /// `tree_depth == asserted_s_bits` (=2 for 3 shards). Stress alone keeps
    /// depth 4 for expand-ramp headroom while initial s stays 2.
    #[test]
    fn presets_tree_depth_matches_s_except_stress_headroom() {
        assert_eq!(BeaconGenesisConfig::mainnet().tree_depth, 2);
        assert_eq!(BeaconGenesisConfig::testnet1().tree_depth, 2);
        assert_eq!(BeaconGenesisConfig::testnet2().tree_depth, 2);
        assert_eq!(BeaconGenesisConfig::devnet().tree_depth, 2);
        assert_eq!(BeaconGenesisConfig::testnet_stress().tree_depth, 4);
        for cfg in [
            BeaconGenesisConfig::mainnet(),
            BeaconGenesisConfig::testnet1(),
            BeaconGenesisConfig::testnet2(),
            BeaconGenesisConfig::devnet(),
        ] {
            assert_eq!(
                cfg.tree_depth, cfg.asserted_s_bits,
                "{:?}: tree_depth should equal asserted_s_bits",
                cfg.network_id
            );
        }
    }

    /// Genesis-lock regression: a genesis TOML/struct predating the
    /// `tree_depth` field must deserialize with the default (2 = standard s),
    /// not fail — same backward-compatibility contract as `shard_expansion`.
    #[test]
    fn tree_depth_defaults_when_omitted_from_toml() {
        let toml_without_tree_depth = r#"
            network_id = "Devnet"
            version = 1
            timestamp = 1704067200
            difficulty = 1
            bits = 486604799
            bitcoin_anchor_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            bitcoin_anchor_height = 0
            bitcoin_anchor_timestamp = 1704067200
            premine = []
            genesis_message = "test"
        "#;
        let cfg: BeaconGenesisConfig = toml::from_str(toml_without_tree_depth)
            .expect("must deserialize without an explicit tree_depth field");
        assert_eq!(cfg.tree_depth, 2, "omitted tree_depth must default to 2");
    }

    #[test]
    fn preset_matches_itself() {
        // validate_matches_preset() compares self against
        // BeaconGenesisConfig::testnet_stress() when network_id == TestnetStress.
        let cfg = BeaconGenesisConfig::testnet_stress();
        cfg.validate_matches_preset().expect("preset must match itself");
    }

    #[test]
    fn network_genesis_config_validates() {
        let cfg = NetworkGenesisConfig::testnet_stress();
        cfg.validate().expect("full network genesis config must validate");
        assert_eq!(&cfg.network_magic, b"SHTS");
    }

    #[test]
    fn faucet_premine_address_decodes_to_real_pubkey() {
        // TS-FAUCET: the faucet's premine entry must be a real "0x" + 64-hex
        // pubkey (spendable), not a human label (BLAKE3-hashed, unspendable).
        use crate::common::blocks::shard_block::address_string_to_recipient;

        let cfg = BeaconGenesisConfig::testnet_stress();
        let faucet = &cfg.premine[0];
        assert!(
            faucet.address.starts_with("0x") && faucet.address.len() == 66,
            "faucet premine address must be a real 0x-prefixed 64-hex pubkey, got {:?}",
            faucet.address
        );

        let expected: [u8; 32] = {
            let bytes = hex::decode(&faucet.address[2..]).expect("valid hex");
            let mut r = [0u8; 32];
            r.copy_from_slice(&bytes);
            r
        };
        assert_eq!(address_string_to_recipient(&faucet.address), expected);
    }

    #[test]
    fn premine_total_matches_plan_approximation() {
        // docs/plan/Testnet_Stress_Launch_Plan.md §3.4: "Total premine ≈ 2.2M coins"
        let cfg = BeaconGenesisConfig::testnet_stress();
        let coins = cfg.total_premine() / 100_000_000;
        assert_eq!(coins, 2_250_000);
    }

    #[test]
    fn genesis_toml_file_matches_rust_preset() {
        // NC-5 fix: `CARGO_MANIFEST_DIR` is `crates/common-types/` post-crate-split,
        // not the repo root this path assumed pre-move (see the sibling
        // `genesis_devnet_15_toml_passes_difficulty_validation` test below, which
        // already had the `../../` prefix). Never caught because this crate's
        // test binary didn't compile until NC-5 was fixed (see
        // docs/plan/Correctness_and_Validation_Plan.md).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/genesis_testnet_stress.toml");
        let from_file = NetworkGenesisConfig::from_file(&path)
            .expect("config/genesis_testnet_stress.toml must parse");
        from_file.validate().expect("file-loaded config must validate");
        from_file
            .beacon
            .validate_matches_preset()
            .expect("file-loaded config must match BeaconGenesisConfig::testnet_stress()");
        // `validate_matches_preset` checks selected fields only; the genesis
        // block hashes every field (e.g. `genesis_message` into the coinbase),
        // so the pinned `expected_hash` holds for both only if they are
        // identical in full. TEST-COV-1: an em-dash vs hyphen in the message
        // slipped past the field-wise check.
        assert_eq!(
            format!("{:#?}", from_file.beacon),
            format!("{:#?}", BeaconGenesisConfig::testnet_stress()),
            "config/genesis_testnet_stress.toml and the Rust preset must be identical",
        );
        assert_eq!(from_file.beacon.network_id, NetworkId::TestnetStress);
        assert_eq!(
            from_file.beacon.total_premine(),
            BeaconGenesisConfig::testnet_stress().total_premine(),
        );
        assert_eq!(from_file.beacon.shard_expansion.epoch_length, 256);
        assert!(
            from_file.beacon.credit_premine_to_shard_genesis,
            "testnet-stress TOML must set credit_premine_to_shard_genesis=true"
        );
        assert_eq!(
            from_file.beacon.credit_premine_to_shard_genesis,
            BeaconGenesisConfig::testnet_stress().credit_premine_to_shard_genesis,
        );
    }

    #[test]
    fn genesis_devnet_15_toml_passes_difficulty_validation() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/genesis_devnet_15.toml");
        let from_file = NetworkGenesisConfig::from_file(&path)
            .expect("config/genesis_devnet_15.toml must parse");
        from_file.validate().expect("file-loaded config must validate");
        from_file
            .beacon
            .validate_difficulty_params()
            .expect("devnet_15 genesis difficulty params must validate");
        assert_eq!(from_file.beacon.bits, 0x0300_0100);
        assert_eq!(from_file.beacon.difficulty, 256);
    }

    /// Pins the epoch-derived maturity per preset (`docs/plan/Coinbase_Maturity_Design.md` §3). A change to the
    /// formula, an epoch length or a calibration must update that table on purpose.
    #[test]
    fn shard_coinbase_maturity_is_derived_per_network() {
        let shard_of = |beacon: &BeaconGenesisConfig| {
            ShardGenesisConfig::from_beacon_genesis(beacon, 0).coinbase_maturity
        };
        // epoch_length 4096, calibration 16: 64 beacon blocks = 1024 shard blocks.
        assert_eq!(shard_of(&BeaconGenesisConfig::mainnet()), 1024);
        assert_eq!(shard_of(&BeaconGenesisConfig::testnet1()), 1024);
        assert_eq!(shard_of(&BeaconGenesisConfig::testnet2()), 1024);
        assert_eq!(shard_of(&BeaconGenesisConfig::devnet()), 1024);
        // epoch_length 256, calibration 16: the 4-block beacon floor = 64 shard blocks.
        assert_eq!(shard_of(&BeaconGenesisConfig::testnet_stress()), 64);
    }

    /// The flat placeholder `from_beacon_anchor` writes before the derivation overwrites it.
    /// Not a production value; kept pinned so nobody reads it as one.
    #[test]
    fn coinbase_maturity_flat_placeholder_is_overwritten_by_derivation() {
        let shard = ShardGenesisConfig::from_beacon_anchor(
            NetworkId::TestnetStress,
            0,
            [1u8; 32],
            0,
            0,
            0,
            1,
            0x0300_0001,
            1000,
            BeaconGenesisConfig::testnet_stress().max_target,
        );
        assert_eq!(shard.coinbase_maturity, 0);
    }
}