// src/common/utxo/coinbase.rs  (updated)
//
// Coinbase transaction builder for beacon chain
//
// Block reward = block_subsidy(height, config) + sum(tx_fees)
//
// The subsidy is looked up from the epoch schedule defined in
// `BeaconSubsidyConfig`; see `beacon_subsidy.rs` for the full
// schedule structure.

use crate::common::utxo::beacon_subsidy::{BeaconSubsidyConfig, total_block_reward};
use log::debug;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Build a beacon chain coinbase transaction.
///
/// The total coinbase output value is:
///
/// ```text
/// total_reward = block_subsidy(height, subsidy_config) + tx_fees
/// ```
///
/// The subsidy is fixed for all blocks within an epoch (4 096 blocks).
/// After 5 grand-epochs (245 760 blocks) the subsidy becomes the
/// permanent `terminal_subsidy` from the config.
///
/// # Arguments
/// * `height`          – 0-based block height (used for subsidy lookup and BIP34)
/// * `subsidy_config`  – validated [`BeaconSubsidyConfig`]
/// * `tx_fees`         – sum of all transaction fees in this block (satoshis)
/// * `pool_wallet`     – destination address for the coinbase output
/// * `timestamp`       – block timestamp (Unix seconds)
/// * `merged_mining_root` – 32-byte merged-mining commitment
/// * `extra_data`      – additional data appended to the coinbase script
///
/// # Returns
/// Binary-serialised coinbase transaction (`Vec<u8>`).
pub fn build_beacon_coinbase_tx(
    height: u32,
    subsidy_config: &BeaconSubsidyConfig,
    tx_fees: u64,
    pool_wallet: &str,
    timestamp: u64,
    merged_mining_root: &[u8; 32],
    extra_data: &[u8],
) -> Result<Vec<u8>, String> {

    // ── 1. Determine reward ──────────────────────────────────────────────────
    let block_reward = total_block_reward(height as u64, subsidy_config, tx_fees)?;

    debug!(
        "Building coinbase: height={}, subsidy+fees={}, wallet={}",
        height, block_reward, pool_wallet
    );

    // ── 2. Serialise transaction ─────────────────────────────────────────────
    let mut tx = Vec::new();

    // Version (4 bytes LE)
    tx.extend_from_slice(&1u32.to_le_bytes());

    // Input count — always 1 for coinbase
    encode_varint(1, &mut tx);
    build_coinbase_input(height, timestamp, merged_mining_root, extra_data, &mut tx)?;

    // Output count — 1 output to pool_wallet
    encode_varint(1, &mut tx);
    build_output(block_reward, pool_wallet, &mut tx)?;

    // Locktime (4 bytes)
    tx.extend_from_slice(&0u32.to_le_bytes());

    debug!("Coinbase transaction built: {} bytes, reward={}", tx.len(), block_reward);
    Ok(tx)
}

/// Return only the total coinbase reward for a block without building the full
/// transaction.  Useful for reward-display / validation paths.
///
/// ```text
/// reward = block_subsidy(height, config) + tx_fees
/// ```
pub fn coinbase_reward_for_height(
    height: u64,
    subsidy_config: &BeaconSubsidyConfig,
    tx_fees: u64,
) -> Result<u64, String> {
    total_block_reward(height, subsidy_config, tx_fees)
}

/// Build a coinbase transaction using a pre-computed flat reward (satoshis).
///
/// Use this when the caller has already determined the block reward externally
/// (e.g. the mining pool's `RewardConfig`), bypassing the subsidy schedule.
pub fn build_beacon_coinbase_tx_with_reward(
    height: u32,
    block_reward: u64,
    pool_wallet: &str,
    timestamp: u64,
    merged_mining_root: &[u8; 32],
    extra_data: &[u8],
) -> Result<Vec<u8>, String> {
    debug!(
        "Building coinbase (flat reward): height={}, reward={}, wallet={}",
        height, block_reward, pool_wallet
    );

    let mut tx = Vec::new();
    tx.extend_from_slice(&1u32.to_le_bytes());
    encode_varint(1, &mut tx);
    build_coinbase_input(height, timestamp, merged_mining_root, extra_data, &mut tx)?;
    encode_varint(1, &mut tx);
    build_output(block_reward, pool_wallet, &mut tx)?;
    tx.extend_from_slice(&0u32.to_le_bytes());

    debug!("Coinbase transaction built: {} bytes, reward={}", tx.len(), block_reward);
    Ok(tx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers  (unchanged from original coinbase.rs)
// ─────────────────────────────────────────────────────────────────────────────

fn build_coinbase_input(
    height: u32,
    timestamp: u64,
    merged_mining_root: &[u8; 32],
    extra_data: &[u8],
    tx: &mut Vec<u8>,
) -> Result<(), String> {
    // Previous output: null (32 bytes of 0x00)
    tx.extend_from_slice(&[0u8; 32]);
    // Previous output index: 0xFFFFFFFF
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let mut script = Vec::new();
    encode_height(height, &mut script);
    script.extend_from_slice(&timestamp.to_le_bytes());
    script.extend_from_slice(merged_mining_root);
    if !extra_data.is_empty() {
        script.extend_from_slice(extra_data);
    }

    encode_varint(script.len() as u64, tx);
    tx.extend_from_slice(&script);

    // Sequence: 0xFFFFFFFF
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    Ok(())
}

fn build_output(value: u64, address: &str, tx: &mut Vec<u8>) -> Result<(), String> {
    tx.extend_from_slice(&value.to_le_bytes());
    let script_pubkey = build_script_pubkey(address)?;
    encode_varint(script_pubkey.len() as u64, tx);
    tx.extend_from_slice(&script_pubkey);
    Ok(())
}

fn build_script_pubkey(address: &str) -> Result<Vec<u8>, String> {
    let pubkey_hash = parse_address_to_hash(address)?;
    let mut script = Vec::new();
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(&pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG
    Ok(script)
}

fn parse_address_to_hash(address: &str) -> Result<[u8; 20], String> {
    let addr = address.trim_start_matches("0x");
    if addr.len() == 40 {
        let bytes = hex::decode(addr)
            .map_err(|e| format!("Invalid address format: {}", e))?;
        if bytes.len() >= 20 {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&bytes[0..20]);
            return Ok(hash);
        }
    }
    // Fallback: SHA-256 of the address string
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(addr.as_bytes());
    let hash = hasher.finalize();
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash[0..20]);
    Ok(result)
}

fn encode_height(height: u32, script: &mut Vec<u8>) {
    if height == 0 {
        script.push(0);
        return;
    }
    let bytes = height.to_le_bytes();
    let mut len = 4usize;
    for i in (0..4).rev() {
        if bytes[i] != 0 {
            len = i + 1;
            break;
        }
    }
    let needs_padding = (bytes[len - 1] & 0x80) != 0;
    if needs_padding {
        script.push((len + 1) as u8);
        script.extend_from_slice(&bytes[0..len]);
        script.push(0);
    } else {
        script.push(len as u8);
        script.extend_from_slice(&bytes[0..len]);
    }
}

fn encode_varint(n: u64, output: &mut Vec<u8>) {
    if n < 0xFD {
        output.push(n as u8);
    } else if n <= 0xFFFF {
        output.push(0xFD);
        output.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        output.push(0xFE);
        output.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        output.push(0xFF);
        output.extend_from_slice(&n.to_le_bytes());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utxo::beacon_subsidy::BeaconSubsidyConfig;
    use crate::common::emission_schedule::{TAIL_EMISSION_ATOMS, PREMINE_ATOMS};

    const WALLET: &str = "0x2DFa7eC2A71E5b1f970B753EAaD1819375811484";
    const ROOT: [u8; 32] = [0u8; 32];

    fn cfg() -> BeaconSubsidyConfig {
        BeaconSubsidyConfig::devnet()
    }

    // ── basic structure ───────────────────────────────────────────────────────

    #[test]
    fn coinbase_has_reasonable_length() {
        let tx = build_beacon_coinbase_tx(
            100, &cfg(), 0, WALLET, 1_234_567_890, &ROOT, b"test",
        ).unwrap();
        assert!(tx.len() > 100 && tx.len() < 500);
    }

    #[test]
    fn version_field_is_1() {
        let tx = build_beacon_coinbase_tx(
            0, &cfg(), 0, WALLET, 0, &ROOT, &[],
        ).unwrap();
        assert_eq!(&tx[0..4], &1u32.to_le_bytes());
    }

    // ── reward encoding ───────────────────────────────────────────────────────

    #[test]
    fn genesis_reward_equals_fees_only() {
        // Genesis block has 0 subsidy; only fees contribute to the total reward.
        let fees = 12_345u64;
        let tx = build_beacon_coinbase_tx(0, &cfg(), fees, WALLET, 0, &ROOT, &[]).unwrap();
        let reward = coinbase_reward_for_height(0, &cfg(), fees).unwrap();
        assert_eq!(reward, fees);
        let _ = tx;
    }

    #[test]
    fn reward_is_constant_at_all_non_genesis_heights() {
        let r0 = coinbase_reward_for_height(1, &cfg(), 0).unwrap();
        let r1 = coinbase_reward_for_height(1_000_000, &cfg(), 0).unwrap();
        assert_eq!(r0, r1);
        assert_eq!(r0, TAIL_EMISSION_ATOMS);
    }

    #[test]
    fn genesis_reward_is_zero_subsidy() {
        // Genesis block has 0 subsidy; premine is validated separately.
        let r = coinbase_reward_for_height(0, &cfg(), 0).unwrap();
        assert_eq!(r, 0);
    }

    #[test]
    fn fees_added_on_top_of_subsidy() {
        let no_fees   = coinbase_reward_for_height(1, &cfg(), 0).unwrap();
        let with_fees = coinbase_reward_for_height(1, &cfg(), 99_999).unwrap();
        assert_eq!(with_fees - no_fees, 99_999);
    }
}
