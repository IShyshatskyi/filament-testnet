// filament-types/src/genesis.rs — minimal genesis config for the light client.

/// Compact rBits of the default starting difficulty (D = 128, the epoch-0 floor of a 3-chain
/// network; Nov 2026). The 15-chain `testnet2` starts at D = 512 (`0x0300_0200`).
pub const GENESIS_DEFAULT_BITS: u32 = 0x0300_0080;

/// Compact rBits of the 15-chain `testnet2` starting difficulty (D = 512).
pub const GENESIS_TESTNET2_BITS: u32 = 0x0300_0200;

pub mod bitcoin_anchors {
    pub const DEVNET_ANCHOR_HASH: [u8; 32] = [
        0x4a, 0xe1, 0x99, 0x82, 0xdf, 0x01, 0xcb, 0x02, 0xb2, 0x82, 0xc9, 0xfd, 0x53, 0x07, 0x65,
        0x99, 0xd5, 0xd2, 0x79, 0x13, 0x33, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    pub const MAINNET_ANCHOR_HASH: [u8; 32] = [0u8; 32];
    pub const TESTNET1_ANCHOR_HASH: [u8; 32] = [
        0x46, 0x22, 0x9c, 0x66, 0xdc, 0xeb, 0x87, 0xcf, 0x6a, 0x56, 0x66, 0x44, 0x8e, 0x29, 0x68,
        0x2b, 0xbe, 0xd8, 0x1f, 0xed, 0x12, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    /// `testnet3` (the former `testnet2`, Nov 2026 rename): its own Bitcoin block.
    pub const TESTNET3_ANCHOR_HASH: [u8; 32] = [
        0x29, 0xd5, 0xd4, 0x23, 0xd7, 0xcb, 0x7e, 0xa3, 0xee, 0x94, 0x45, 0x2d, 0x61, 0x0a, 0xcb,
        0x93, 0x13, 0xa3, 0x8f, 0xf9, 0xfd, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    /// `testnet2` (15 chains) shares the `testnet1` anchor.
    pub const TESTNET2_ANCHOR_HASH: [u8; 32] = TESTNET1_ANCHOR_HASH;
    /// The local `testnet-stress` profile's own Bitcoin block.
    pub const TESTNET_STRESS_ANCHOR_HASH: [u8; 32] = [
        0x69, 0x74, 0x20, 0x91, 0x76, 0xd5, 0xa4, 0xb1, 0xfd, 0xb1, 0xa2, 0xa1, 0x46, 0xae, 0x82,
        0x65, 0xdf, 0xbd, 0x30, 0xb2, 0xf2, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
}

pub const SHARD_CALIBRATION_CONSTANT: u64 = 16;

/// CPU-oriented initial target ceiling, 2^240 (`devnet`, `testnet1`, `testnet2`, `testnet-stress`).
pub const GENESIS_MAX_TARGET_CPU: [u8; 32] = {
    let mut t = [0u8; 32];
    t[1] = 0x01;
    t
};
/// `testnet3`'s ASIC-oriented initial target ceiling, 2^216.
pub const GENESIS_MAX_TARGET_TESTNET3: [u8; 32] = {
    let mut t = [0u8; 32];
    t[4] = 0x01;
    t
};
/// `mainnet`'s initial target ceiling, 2^212.
pub const GENESIS_MAX_TARGET_ASIC: [u8; 32] = {
    let mut t = [0u8; 32];
    t[5] = 0x10;
    t
};

/// Shard-expansion parameters of a genesis (the slice a light client needs). Defaults are the
/// node's: 3 chains at s = 2, a 5/8 vote, one quarter step, 16 blocks of activation delay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct ExpandVotingConfig {
    #[serde(default = "d_initial_shard_count")]
    pub initial_shard_count: u16,
    #[serde(default = "d_initial_s_bits")]
    pub initial_s_bits: u8,
    #[serde(default = "d_threshold_numerator")]
    pub threshold_numerator: u64,
    #[serde(default = "d_threshold_denominator")]
    pub threshold_denominator: u64,
    #[serde(default = "d_step_numerator")]
    pub step_numerator: u16,
    #[serde(default = "d_step_denominator")]
    pub step_denominator: u16,
    #[serde(default = "d_activation_delay")]
    pub activation_delay: u32,
    #[serde(default = "d_epoch_length")]
    pub epoch_length: u32,
}

fn d_initial_shard_count() -> u16 { 3 }
fn d_initial_s_bits() -> u8 { 2 }
fn d_threshold_numerator() -> u64 { 5 }
fn d_threshold_denominator() -> u64 { 8 }
fn d_step_numerator() -> u16 { 1 }
fn d_step_denominator() -> u16 { 4 }
fn d_activation_delay() -> u32 { 16 }
fn d_epoch_length() -> u32 { crate::expand_voting::DEFAULT_EPOCH_LENGTH }

impl Default for ExpandVotingConfig {
    fn default() -> Self {
        Self {
            initial_shard_count: d_initial_shard_count(),
            initial_s_bits: d_initial_s_bits(),
            threshold_numerator: d_threshold_numerator(),
            threshold_denominator: d_threshold_denominator(),
            step_numerator: d_step_numerator(),
            step_denominator: d_step_denominator(),
            activation_delay: d_activation_delay(),
            epoch_length: d_epoch_length(),
        }
    }
}

/// The slice of a beacon genesis a light client needs: starting difficulty, the Bitcoin anchor, the
/// target ceiling, the frozen hash-sorting width, and the shard parameters. Parsed from the same
/// genesis files as the node; fields the client does not use are ignored. The shared vectors check
/// every preset and every checked-in genesis file against the node's parse.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct BeaconGenesisConfig {
    pub bits: u32,
    #[serde(default, deserialize_with = "anchor::deserialize")]
    pub bitcoin_anchor_hash: [u8; 32],
    #[serde(default = "default_max_target")]
    pub max_target: [u8; 32],
    #[serde(default = "default_asserted_s_bits")]
    pub asserted_s_bits: u32,
    #[serde(default = "default_minimum_difficulty")]
    pub minimum_difficulty: u64,
    #[serde(default = "default_tree_depth")]
    pub tree_depth: u32,
    #[serde(default = "default_shard_calibration")]
    pub shard_calibration: u32,
    #[serde(default)]
    pub shard_expansion: ExpandVotingConfig,
}

fn default_max_target() -> [u8; 32] {
    GENESIS_MAX_TARGET_CPU
}
fn default_asserted_s_bits() -> u32 { 2 }
fn default_minimum_difficulty() -> u64 { 128 }
fn default_tree_depth() -> u32 { 2 }
fn default_shard_calibration() -> u32 { SHARD_CALIBRATION_CONSTANT as u32 }

mod anchor {
    use serde::de::{self, Deserializer, SeqAccess, Visitor};

    /// The anchor hash is written as 32 integers in the genesis files, or as a hex string.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a 32-byte array or a 64-character hex string")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let bytes = hex::decode(s.trim()).map_err(E::custom)?;
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| E::custom("anchor hash must be 32 bytes"))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 32];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(33, &self));
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(V)
    }
}

impl BeaconGenesisConfig {
    #[allow(clippy::too_many_arguments)]
    fn preset(
        anchor: [u8; 32],
        bits: u32,
        max_target: [u8; 32],
        asserted_s_bits: u32,
        tree_depth: u32,
        shard_expansion: ExpandVotingConfig,
    ) -> Self {
        Self {
            bits,
            bitcoin_anchor_hash: anchor,
            max_target,
            asserted_s_bits,
            minimum_difficulty: 128,
            tree_depth,
            shard_calibration: SHARD_CALIBRATION_CONSTANT as u32,
            shard_expansion,
        }
    }

    fn delayed(activation_delay: u32) -> ExpandVotingConfig {
        ExpandVotingConfig { activation_delay, ..ExpandVotingConfig::default() }
    }

    pub fn mainnet() -> Self {
        Self::preset(bitcoin_anchors::MAINNET_ANCHOR_HASH, GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_ASIC, 2, 2, Self::delayed(4))
    }
    pub fn testnet1() -> Self {
        Self::preset(bitcoin_anchors::TESTNET1_ANCHOR_HASH, GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 2, Self::delayed(4))
    }
    /// 15 chains at s = 4, starting difficulty 512.
    pub fn testnet2() -> Self {
        let expansion = ExpandVotingConfig {
            initial_shard_count: 15,
            initial_s_bits: 4,
            activation_delay: 4,
            ..ExpandVotingConfig::default()
        };
        let mut cfg = Self::preset(bitcoin_anchors::TESTNET2_ANCHOR_HASH, GENESIS_TESTNET2_BITS, GENESIS_MAX_TARGET_CPU, 4, 4, expansion);
        cfg.minimum_difficulty = 512;
        cfg
    }
    pub fn testnet3() -> Self {
        Self::preset(bitcoin_anchors::TESTNET3_ANCHOR_HASH, GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_TESTNET3, 2, 2, Self::delayed(4))
    }
    pub fn devnet() -> Self {
        Self::preset(bitcoin_anchors::DEVNET_ANCHOR_HASH, GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 2, Self::delayed(1))
    }
    /// The local stress profile: 3 chains, a 16-leaf tree, epochs of 256 blocks.
    pub fn testnet_stress() -> Self {
        let expansion = ExpandVotingConfig { activation_delay: 1, epoch_length: 256, step_denominator: 2, ..ExpandVotingConfig::default() };
        Self::preset(bitcoin_anchors::TESTNET_STRESS_ANCHOR_HASH, GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 4, expansion)
    }
}

/// Shard genesis arithmetic.
pub struct ShardGenesisConfig;

impl ShardGenesisConfig {
    /// Starting rBits of a shard: the beacon's difficulty divided by the calibration (at least 1).
    pub fn bits_from_beacon_nbits(beacon_rbits: u32, shard_calibration: u32) -> u32 {
        use crate::weighted_hash::{rbits_to_u128_approx, u128_to_rbits};
        let d_beacon = rbits_to_u128_approx(beacon_rbits).max(1);
        let cal = shard_calibration.max(1) as u128;
        u128_to_rbits((d_beacon / cal).max(1))
    }
}
