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
    #[serde(default = "default_network_id")]
    pub network_id: NetworkId,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub difficulty: u64,
    pub bits: u32,
    #[serde(default)]
    pub bitcoin_anchor_height: u32,
    #[serde(default)]
    pub bitcoin_anchor_timestamp: u64,
    #[serde(default)]
    pub premine: Vec<PremineOutput>,
    #[serde(default)]
    pub genesis_message: String,
    #[serde(default, deserialize_with = "opt_hash::deserialize")]
    pub expected_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub nonce: Option<u64>,
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
fn default_network_id() -> NetworkId { NetworkId::Custom }
fn default_version() -> u32 { 1 }

/// Network identifier of a genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum NetworkId {
    Mainnet,
    Testnet1,
    Testnet2,
    Testnet3,
    Devnet,
    TestnetStress,
    Custom,
}

/// One premine entry: an address label or `0x` + 64 hex (a real key), and an amount in atoms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct PremineOutput {
    pub address: String,
    pub amount: u64,
    #[serde(default)]
    pub description: Option<String>,
}

mod opt_hash {
    use serde::de::{Deserialize, Deserializer};
    /// The pinned hash is written as 32 integers in the genesis files.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<[u8; 32]>::deserialize(d)
    }
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
        network_id: NetworkId,
        anchor: [u8; 32],
        anchor_height: u32,
        anchor_timestamp: u64,
        timestamp: u64,
        difficulty: u64,
        bits: u32,
        max_target: [u8; 32],
        asserted_s_bits: u32,
        tree_depth: u32,
        shard_expansion: ExpandVotingConfig,
        premine: Vec<PremineOutput>,
        genesis_message: &str,
    ) -> Self {
        Self {
            network_id,
            version: 1,
            timestamp,
            difficulty,
            bits,
            bitcoin_anchor_height: anchor_height,
            bitcoin_anchor_timestamp: anchor_timestamp,
            premine,
            genesis_message: genesis_message.to_string(),
            expected_hash: None,
            nonce: None,
            bitcoin_anchor_hash: anchor,
            max_target,
            asserted_s_bits,
            minimum_difficulty: difficulty.max(128),
            tree_depth,
            shard_calibration: SHARD_CALIBRATION_CONSTANT as u32,
            shard_expansion,
        }
    }

    fn delayed(activation_delay: u32) -> ExpandVotingConfig {
        ExpandVotingConfig { activation_delay, ..ExpandVotingConfig::default() }
    }

    fn one(address: &str, amount: u64) -> Vec<PremineOutput> {
        vec![PremineOutput { address: address.to_string(), amount, description: None }]
    }

    pub fn mainnet() -> Self {
        Self::preset(
            NetworkId::Mainnet, bitcoin_anchors::MAINNET_ANCHOR_HASH, 0, 1704067200, 1704067200, 128,
            GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_ASIC, 2, 2, Self::delayed(4),
            Self::one("bc1q...", 2_100_000_000_000_000), "The Times 01/Jan/2024 Shisha Network Launch",
        )
    }
    pub fn testnet1() -> Self {
        Self::preset(
            NetworkId::Testnet1, bitcoin_anchors::TESTNET1_ANCHOR_HASH, 935092, 1704067200, 1704067200, 128,
            GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 2, Self::delayed(4),
            Self::one("test1q...", 10_000_000_000), "Shisha Network Testnet 1",
        )
    }
    /// 15 chains at s = 4, starting difficulty 512.
    pub fn testnet2() -> Self {
        let expansion = ExpandVotingConfig {
            initial_shard_count: 15,
            initial_s_bits: 4,
            activation_delay: 4,
            ..ExpandVotingConfig::default()
        };
        Self::preset(
            NetworkId::Testnet2, bitcoin_anchors::TESTNET2_ANCHOR_HASH, 935092, 1704067200, 1704067200, 512,
            GENESIS_TESTNET2_BITS, GENESIS_MAX_TARGET_CPU, 4, 4, expansion,
            Self::one("testnet-faucet", 10_000_000_000), "Shisha Network Testnet2 - Public 15-shard network",
        )
    }
    pub fn testnet3() -> Self {
        Self::preset(
            NetworkId::Testnet3, bitcoin_anchors::TESTNET3_ANCHOR_HASH, 935091, 1704067200, 1704067200, 128,
            GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_TESTNET3, 2, 2, Self::delayed(4),
            Self::one("test2q...", 10_000_000_000), "Shisha Network Testnet 3",
        )
    }
    pub fn devnet() -> Self {
        Self::preset(
            NetworkId::Devnet, bitcoin_anchors::DEVNET_ANCHOR_HASH, 935093, 1704067200, 1704067200, 128,
            GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 2, Self::delayed(1), Vec::new(),
            "Shisha Network Devnet",
        )
    }
    /// The local stress profile: 3 chains, a 16-leaf tree, epochs of 256 blocks, a pinned genesis hash.
    pub fn testnet_stress() -> Self {
        let expansion = ExpandVotingConfig { activation_delay: 1, epoch_length: 256, step_denominator: 2, ..ExpandVotingConfig::default() };
        let premine = [
            ("0xd5c98a0cd803f46579317eeda18c965d225959f9c4e6d027b82725e7fa95cd0f", 100_000_000_000_000),
            ("teststress1-producer-a-treasury", 50_000_000_000_000),
            ("teststress1-producer-b-treasury", 25_000_000_000_000),
            ("0x0dc31d5ee594bd2cc3d99fc27065d986edf574fcf8d16d8ba2955ce50d2b47d2", 5_000_000_000_000),
            ("0x5beebbf8c70cd026ee2730511e98514870e78e59ad36b7844c06c220a08a4882", 5_000_000_000_000),
            ("0x809a55c2a4cc37497f86d7174dd29cc04ab44bc7578d887ca666eb9998e28563", 5_000_000_000_000),
            ("0x97e3ea6ab9e673f66e92656b7f3a4de00c45a6d464468c37ed07cacacc68f16a", 5_000_000_000_000),
            ("0x740595e7f8c275a516631134698fed3bd288b17d386d5aa9802605915bde5d9e", 5_000_000_000_000),
            ("0x76f26eb10684ace464fc39b74030267e6f322980d6645073af9788c51ebf113a", 5_000_000_000_000),
            ("0x4b91a5253bd70d2459cc271ba768662cafc14059ced18efb6cad6b2cd981fdf1", 5_000_000_000_000),
            ("0x95208050262701824f919a94ca509d130b1f3a13ad349ea638004d50bcc57072", 5_000_000_000_000),
            ("teststress1-filament-demo", 10_000_000_000_000)
        ]
        .iter()
        .map(|(a, v)| PremineOutput { address: a.to_string(), amount: *v, description: None })
        .collect();
        let mut cfg = Self::preset(
            NetworkId::TestnetStress, bitcoin_anchors::TESTNET_STRESS_ANCHOR_HASH, 964050, 1787689496, 1787689496, 128,
            GENESIS_DEFAULT_BITS, GENESIS_MAX_TARGET_CPU, 2, 4, expansion, premine,
            "Shisha Network Testnet-Stress - 30-day stress launch",
        );
        cfg.nonce = Some(89721);
        cfg.expected_hash = Some(hex_hash("000003209cb9d6d5f025b849177c322c66bf0e814cdf3558132fbd0203000080"));
        cfg
    }
}

fn hex_hash(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(s).expect("hex"));
    out
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
