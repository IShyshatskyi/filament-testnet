// filament-types/src/genesis.rs — minimal genesis config for the light client.

pub const GENESIS_DEFAULT_BITS: u32 = 0x0300_0040;

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
    pub const TESTNET2_ANCHOR_HASH: [u8; 32] = [
        0x29, 0xd5, 0xd4, 0x23, 0xd7, 0xcb, 0x7e, 0xa3, 0xee, 0x94, 0x45, 0x2d, 0x61, 0x0a, 0xcb,
        0x93, 0x13, 0xa3, 0x8f, 0xf9, 0xfd, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
}

pub const SHARD_CALIBRATION_CONSTANT: u64 = 16;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct BeaconGenesisConfig {
    pub bits: u32,
    #[serde(default, with = "anchor_hex")]
    pub bitcoin_anchor_hash: [u8; 32],
    #[serde(default = "default_max_target")]
    pub max_target: [u8; 32],
    #[serde(default)]
    pub asserted_s_bits: u32,
}

fn default_max_target() -> [u8; 32] {
    [0xff; 32]
}

mod anchor_hex {
    use serde::Deserialize;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer).unwrap_or_default();
        let bytes = hex::decode(s.trim()).unwrap_or_default();
        let mut out = [0u8; 32];
        if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
        }
        Ok(out)
    }
}

impl BeaconGenesisConfig {
    fn with_anchor(anchor: [u8; 32]) -> Self {
        Self {
            bits: GENESIS_DEFAULT_BITS,
            bitcoin_anchor_hash: anchor,
            max_target: [0xff; 32],
            asserted_s_bits: 0,
        }
    }

    pub fn mainnet() -> Self {
        Self::with_anchor(bitcoin_anchors::MAINNET_ANCHOR_HASH)
    }
    pub fn testnet1() -> Self {
        Self::with_anchor(bitcoin_anchors::TESTNET1_ANCHOR_HASH)
    }
    pub fn testnet2() -> Self {
        Self::with_anchor(bitcoin_anchors::TESTNET2_ANCHOR_HASH)
    }
    pub fn devnet() -> Self {
        Self::with_anchor(bitcoin_anchors::DEVNET_ANCHOR_HASH)
    }
    pub fn testnet_stress() -> Self {
        Self::testnet2()
    }
}
