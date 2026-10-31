//! Escrow policy-hash helpers for the Filament wallet (D14 surface).
//! Clean-room subset — no validation/UTXO engines.

use crate::transaction_impl::WitnessEntry;

pub const WITNESS_TYPE_ESCROW_COOP: u8 = 0x02;
pub const WITNESS_TYPE_ESCROW_RECOVERY: u8 = 0x03;
pub const ESCROW_POLICY_LEN: usize = 68;
pub const ESCROW_COOP_WITNESS_LEN: usize = 1 + ESCROW_POLICY_LEN + 64 + 64;
pub const ESCROW_RECOVERY_WITNESS_LEN: usize = 1 + ESCROW_POLICY_LEN + 64;
pub const ESCROW_POLICY_TAG: &[u8] = b"shisha/escrow2of2/v1";
pub const ESCROW_SIGHASH_TAG: &[u8] = b"shisha/escrow-sighash/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowPolicy {
    pub sender_pk: [u8; 32],
    pub provider_pk: [u8; 32],
    pub unlock_height: u32,
}

impl EscrowPolicy {
    pub fn to_bytes(&self) -> [u8; ESCROW_POLICY_LEN] {
        let mut b = [0u8; ESCROW_POLICY_LEN];
        b[..32].copy_from_slice(&self.sender_pk);
        b[32..64].copy_from_slice(&self.provider_pk);
        b[64..].copy_from_slice(&self.unlock_height.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != ESCROW_POLICY_LEN {
            return None;
        }
        let mut sender_pk = [0u8; 32];
        let mut provider_pk = [0u8; 32];
        sender_pk.copy_from_slice(&b[..32]);
        provider_pk.copy_from_slice(&b[32..64]);
        let unlock_height = u32::from_le_bytes(b[64..68].try_into().ok()?);
        Some(Self {
            sender_pk,
            provider_pk,
            unlock_height,
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        escrow_policy_hash(&self.to_bytes())
    }
}

pub fn escrow_policy_hash(policy: &[u8; ESCROW_POLICY_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ESCROW_POLICY_TAG);
    h.update(policy);
    h.finalize().into()
}

pub fn escrow_sighash(sighash_v2: &[u8; 32], path_byte: u8) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ESCROW_SIGHASH_TAG);
    h.update(sighash_v2);
    h.update(&[path_byte]);
    h.finalize().into()
}

pub fn coop_witness(
    policy: &EscrowPolicy,
    sig_sender: &[u8; 64],
    sig_provider: &[u8; 64],
) -> WitnessEntry {
    let mut d = Vec::with_capacity(ESCROW_COOP_WITNESS_LEN);
    d.push(WITNESS_TYPE_ESCROW_COOP);
    d.extend_from_slice(&policy.to_bytes());
    d.extend_from_slice(sig_sender);
    d.extend_from_slice(sig_provider);
    WitnessEntry { witness_data: d }
}

pub fn recovery_witness(policy: &EscrowPolicy, sig_sender: &[u8; 64]) -> WitnessEntry {
    let mut d = Vec::with_capacity(ESCROW_RECOVERY_WITNESS_LEN);
    d.push(WITNESS_TYPE_ESCROW_RECOVERY);
    d.extend_from_slice(&policy.to_bytes());
    d.extend_from_slice(sig_sender);
    WitnessEntry { witness_data: d }
}
