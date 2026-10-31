//! Canonical premine → positional outpoint mapping (TS-T-15).
//!
//! Shard chains credit premine on the **first mined block** (height 0) via
//! `build_shard_coinbase_transaction_with_premine`: output 0 is the pool
//! reward; outputs 1..N mirror `BeaconGenesisConfig::premine` in TOML order.
//!
//! Beacon genesis coinbase (informational — not spendable via shard mempool):
//! output 0 is OP_RETURN; outputs 1..N mirror the same premine list.

use serde::{Deserialize, Serialize};

use super::genesis_config::PremineOutput;
use crate::common::blocks::shard_block::address_string_to_recipient;

/// Reserved coinbase slot before the first premine output on a shard block.
pub const SHARD_POOL_REWARD_OUTPUT_IDX: u16 = 0;
/// First premine entry lands at this index on shard height 0.
pub const SHARD_FIRST_PREMINE_OUTPUT_IDX: u16 = 1;

/// OP_RETURN commitment on beacon genesis height 0.
pub const BEACON_OP_RETURN_OUTPUT_IDX: u16 = 0;
/// First premine entry on beacon genesis height 0.
pub const BEACON_FIRST_PREMINE_OUTPUT_IDX: u16 = 1;

/// Height of the shard block that credits premine when
/// `credit_premine_to_shard_genesis` is enabled.
pub const SHARD_PREMINE_BLOCK_HEIGHT: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PremineRole {
    OpReturn,
    PoolReward,
    Faucet,
    ProducerTreasury,
    SpamWallet,
    FilamentDemo,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PremineOutpointEntry {
    /// Index within `BeaconGenesisConfig::premine` (0-based); `None` for reserved slots (pool reward, OP_RETURN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub premine_index: Option<u16>,
    /// Positional output index `(height, output_idx)` within the block.
    pub output_idx: u16,
    /// Block height (0 for genesis-credited premine).
    pub height: u32,
    pub amount_atoms: u64,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub role: PremineRole,
    /// Flat `TxOutput.recipient` (32-byte x-only pubkey or BLAKE3 placeholder).
    pub recipient_hex: String,
    /// True when a real 0x+64-hex address was supplied (spendable if key known).
    pub has_real_pubkey: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PremineOutpointTable {
    pub network_id: String,
    pub genesis_file: String,
    pub credit_premine_to_shard_genesis: bool,
    /// Shard height-0 coinbase (what tx-spammer / faucet spend).
    pub shard_height_0: Vec<PremineOutpointEntry>,
    /// Beacon genesis coinbase (reference only — no shard mempool path).
    pub beacon_height_0: Vec<PremineOutpointEntry>,
}

impl PremineOutpointTable {
    pub fn from_beacon_premine(
        network_id: &str,
        genesis_file: &str,
        credit_premine_to_shard_genesis: bool,
        premine: &[PremineOutput],
    ) -> Self {
        Self {
            network_id: network_id.to_string(),
            genesis_file: genesis_file.to_string(),
            credit_premine_to_shard_genesis,
            shard_height_0: shard_premine_outpoints(premine),
            beacon_height_0: beacon_premine_outpoints(premine),
        }
    }

    /// All spam-wallet entries on shard height 0 (TS-T-10 inputs).
    pub fn spam_wallets(&self) -> impl Iterator<Item = &PremineOutpointEntry> {
        self.shard_height_0
            .iter()
            .filter(|e| e.role == PremineRole::SpamWallet)
    }

    pub fn faucet_shard_outpoint(&self) -> Option<&PremineOutpointEntry> {
        self.shard_height_0
            .iter()
            .find(|e| e.role == PremineRole::Faucet)
    }
}

/// Shard first-mined block (height 0): idx 0 = pool reward, then premine rows.
pub fn shard_premine_outpoints(premine: &[PremineOutput]) -> Vec<PremineOutpointEntry> {
    let mut out = Vec::with_capacity(1 + premine.len());
    out.push(PremineOutpointEntry {
        premine_index: None,
        output_idx: SHARD_POOL_REWARD_OUTPUT_IDX,
        height: SHARD_PREMINE_BLOCK_HEIGHT,
        amount_atoms: 0,
        address: String::new(),
        description: Some("Pool coinbase reward (not a premine entry)".to_string()),
        role: PremineRole::PoolReward,
        recipient_hex: String::new(),
        has_real_pubkey: false,
    });
    for (i, entry) in premine.iter().enumerate() {
        let premine_index = u16::try_from(i).expect("premine list fits u16");
        let output_idx = SHARD_FIRST_PREMINE_OUTPUT_IDX
            .checked_add(premine_index)
            .expect("premine output index fits u16");
        out.push(entry_to_outpoint(
            entry,
            Some(premine_index),
            output_idx,
            SHARD_PREMINE_BLOCK_HEIGHT,
        ));
    }
    out
}

/// Beacon genesis block (height 0): idx 0 = OP_RETURN, then premine rows.
pub fn beacon_premine_outpoints(premine: &[PremineOutput]) -> Vec<PremineOutpointEntry> {
    let mut out = Vec::with_capacity(1 + premine.len());
    out.push(PremineOutpointEntry {
        premine_index: None,
        output_idx: BEACON_OP_RETURN_OUTPUT_IDX,
        height: 0,
        amount_atoms: 0,
        address: String::new(),
        description: Some("OP_RETURN genesis commitment (unspendable)".to_string()),
        role: PremineRole::OpReturn,
        recipient_hex: String::new(),
        has_real_pubkey: false,
    });
    for (i, entry) in premine.iter().enumerate() {
        let premine_index = u16::try_from(i).expect("premine list fits u16");
        let output_idx = BEACON_FIRST_PREMINE_OUTPUT_IDX
            .checked_add(premine_index)
            .expect("premine output index fits u16");
        out.push(entry_to_outpoint(entry, Some(premine_index), output_idx, 0));
    }
    out
}

fn entry_to_outpoint(
    entry: &PremineOutput,
    premine_index: Option<u16>,
    output_idx: u16,
    height: u32,
) -> PremineOutpointEntry {
    let recipient = address_string_to_recipient(&entry.address);
    let has_real_pubkey = entry.address.trim().starts_with("0x")
        || entry.address.trim().starts_with("0X");
    PremineOutpointEntry {
        premine_index,
        output_idx,
        height,
        amount_atoms: entry.amount,
        address: entry.address.clone(),
        description: entry.description.clone(),
        role: classify_premine_role(&entry.address, entry.description.as_deref()),
        recipient_hex: hex::encode(recipient),
        has_real_pubkey,
    }
}

fn classify_premine_role(address: &str, description: Option<&str>) -> PremineRole {
    let desc = description.unwrap_or("").to_ascii_lowercase();
    let addr = address.to_ascii_lowercase();
    if desc.contains("faucet") || addr.contains("faucet") {
        return PremineRole::Faucet;
    }
    if desc.contains("spam") || addr.contains("spam-wallet") {
        return PremineRole::SpamWallet;
    }
    if desc.contains("filament") {
        return PremineRole::FilamentDemo;
    }
    if desc.contains("producer") || desc.contains("treasury") {
        return PremineRole::ProducerTreasury;
    }
    PremineRole::Other
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::genesis::genesis_config::BeaconGenesisConfig;

    #[test]
    fn testnet_stress_spam_wallet_indices_match_ts_t_10_config() {
        let cfg = BeaconGenesisConfig::testnet_stress();
        let table = PremineOutpointTable::from_beacon_premine(
            "TestnetStress",
            "config/genesis_testnet_stress.toml",
            cfg.credit_premine_to_shard_genesis,
            &cfg.premine,
        );
        let spam: Vec<_> = table.spam_wallets().collect();
        assert_eq!(spam.len(), 8, "expected 8 spam wallets in testnet-stress genesis");
        assert_eq!(spam[0].output_idx, 4, "first spam wallet is premine[3] → shard idx 4");
        assert_eq!(spam[0].amount_atoms, 5_000_000_000_000);
        assert_eq!(spam[7].output_idx, 11, "last spam wallet is premine[10] → shard idx 11");

        let faucet = table.faucet_shard_outpoint().expect("faucet entry");
        assert_eq!(faucet.output_idx, 1);
        assert!(faucet.has_real_pubkey, "faucet must use 0x+hex pubkey");
    }

    #[test]
    fn genesis_toml_premine_order_matches_rust_preset() {
        let path = std::path::Path::new("config/genesis_testnet_stress.toml");
        if !path.exists() {
            return;
        }
        let from_file =
            crate::common::genesis::genesis_config::NetworkGenesisConfig::from_file(path)
                .expect("parse genesis TOML");
        let preset = BeaconGenesisConfig::testnet_stress();
        assert_eq!(
            from_file.beacon.premine.len(),
            preset.premine.len(),
            "premine entry count"
        );
        for (a, b) in from_file.beacon.premine.iter().zip(preset.premine.iter()) {
            assert_eq!(a.address, b.address);
            assert_eq!(a.amount, b.amount);
        }
    }
}
