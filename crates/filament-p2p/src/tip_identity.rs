//! Compact tip identity (ShishaNet v16 handshake trailer).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTipIdentity {
    pub height: u32,
    pub prev_mmr_root: [u8; 32],
    pub tip_mmr_root: [u8; 32],
}

impl ChainTipIdentity {
    pub const WIRE_LEN: usize = 4 + 32 + 32;

    pub fn encode(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.height.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_mmr_root);
        out[36..68].copy_from_slice(&self.tip_mmr_root);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::WIRE_LEN {
            return Err(format!(
                "tip identity too short: need {}, have {}",
                Self::WIRE_LEN,
                data.len()
            ));
        }
        Ok(Self {
            height: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            prev_mmr_root: data[4..36].try_into().unwrap(),
            tip_mmr_root: data[36..68].try_into().unwrap(),
        })
    }
}
