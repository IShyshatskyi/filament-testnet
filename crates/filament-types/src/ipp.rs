//! Instant payment provider message shapes used by Filament escrow HTTP API.

use serde::{Deserialize, Serialize};

pub const IPP_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prevout {
    pub value_atoms: u64,
    pub recipient_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayHalfSign {
    pub version: u32,
    pub session_id: String,
    pub payment_request_id: String,
    pub chain_id: u16,
    pub tx_hex: String,
    pub payer_sigs_hex: Vec<String>,
    pub prevouts: Vec<Prevout>,
}
