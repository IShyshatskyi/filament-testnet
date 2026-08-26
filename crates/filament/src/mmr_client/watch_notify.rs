// crates/filament/src/mmr_client/watch_notify.rs
//
// FUD-5 / LC-45..LC-47c — Filament-side processing of Keystone watch notifications
// (TxInclusionNotif / TxSpentNotif / TxRevertNotif).
//
// Design reference: `docs/plan/P2P_Phase10_Plan.md` §6.2

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use common_types::common::proofs::WeightedMMRBatchProof;

use super::invoice::{InvoiceStore, InvoiceError};

/// Default blocks after inclusion before an invoice transitions to `Confirmed`.
/// Overridable via `FilamentNodeConfig.confirmation_depth` (smoke soaks use 1–2).
pub const MIN_CONFIRMATION_DEPTH: u32 = 6;

/// HTTP light-client registrations use peer ids in this range on Keystone.
pub const HTTP_WATCH_PEER_ID_BASE: u64 = 0xF110_0000_0000_0000;

/// A UTXO learned from a verified `TxInclusionNotif`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchUtxo {
    pub shard_id:    u16,
    pub height:      u32,
    pub output_idx:  u16,
    pub value_atoms: u64,
    pub address:     [u8; 32],
}

/// Cap on recorded `verify_with_anchor` samples (TS-F-3).
const PROOF_LATENCY_CAP: usize = 64;

/// Local UTXO set maintained from watch notifications (Path 2).
#[derive(Clone, Debug, Default)]
pub struct WatchNotifyState {
    utxos: HashMap<(u16, u32, u16), WatchUtxo>,
    /// Most recent proof-verify durations in microseconds (newest last).
    proof_verify_us: VecDeque<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InclusionApplyResult {
    /// Proof verified; UTXO recorded.
    Accepted,
    /// Corrupted or unparseable MMR proof — no state change.
    InvalidProof,
}

impl WatchNotifyState {
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    pub fn get_utxo(&self, shard_id: u16, height: u32, output_idx: u16) -> Option<&WatchUtxo> {
        self.utxos.get(&(shard_id, height, output_idx))
    }

    pub fn utxos_for_address(&self, address: &[u8; 32], shard_id: u16) -> Vec<&WatchUtxo> {
        self.utxos
            .values()
            .filter(|u| u.address == *address && u.shard_id == shard_id)
            .collect()
    }

    /// TS-F-3: last N proof-verify samples (µs), oldest first.
    pub fn proof_verify_samples_us(&self) -> Vec<u64> {
        self.proof_verify_us.iter().copied().collect()
    }

    fn record_proof_verify_us(&mut self, us: u64) {
        if self.proof_verify_us.len() >= PROOF_LATENCY_CAP {
            self.proof_verify_us.pop_front();
        }
        self.proof_verify_us.push_back(us);
    }

    /// LC-45 / LC-47: verify proof, then insert UTXO on success.
    pub fn apply_inclusion(
        &mut self,
        shard_id: u16,
        height: u32,
        output_idx: u16,
        value_atoms: u64,
        address: [u8; 32],
        mmr_proof_bytes: &[u8],
        genesis_anchor: [u8; 32],
    ) -> InclusionApplyResult {
        let started = Instant::now();
        let ok = verify_inclusion_proof_bytes(mmr_proof_bytes, genesis_anchor);
        self.record_proof_verify_us(started.elapsed().as_micros() as u64);
        if !ok {
            return InclusionApplyResult::InvalidProof;
        }
        self.utxos.insert(
            (shard_id, height, output_idx),
            WatchUtxo {
                shard_id,
                height,
                output_idx,
                value_atoms,
                address,
            },
        );
        InclusionApplyResult::Accepted
    }

    /// LC-46: remove a spent UTXO if we were tracking it.
    pub fn apply_spent(
        &mut self,
        shard_id: u16,
        output_height: u32,
        output_idx: u16,
    ) -> bool {
        self.utxos.remove(&(shard_id, output_height, output_idx)).is_some()
    }

    /// Remove a UTXO reverted by chain reorg.
    pub fn apply_revert(
        &mut self,
        shard_id: u16,
        height: u32,
        output_idx: u16,
    ) -> bool {
        self.utxos.remove(&(shard_id, height, output_idx)).is_some()
    }
}

/// Deserialise and verify a serialised `WeightedMMRBatchProof`.
pub fn verify_inclusion_proof_bytes(mmr_proof_bytes: &[u8], genesis_anchor: [u8; 32]) -> bool {
    if mmr_proof_bytes.is_empty() {
        return false;
    }
    let Ok((proof, _)) = bincode::serde::decode_from_slice::<WeightedMMRBatchProof, _>(
        mmr_proof_bytes,
        bincode::config::standard(),
    ) else {
        return false;
    };
    proof.verify_with_anchor(genesis_anchor)
}

/// Derive a stable Keystone `peer_id` for HTTP watch registration.
pub fn http_watch_peer_id(client_token: &[u8]) -> u64 {
    let hash = blake3::hash(client_token);
    let lo = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
    HTTP_WATCH_PEER_ID_BASE | (lo & 0x0000_FFFF_FFFF_FFFF)
}

/// Process one inclusion notification end-to-end (UTXO + invoice).
pub fn process_inclusion_notif(
    watch: &mut WatchNotifyState,
    store: &InvoiceStore,
    shard_id: u16,
    height: u32,
    output_idx: u16,
    value_atoms: u64,
    address: [u8; 32],
    mmr_proof_bytes: Vec<u8>,
    genesis_anchor: [u8; 32],
) -> Result<(InclusionApplyResult, Option<[u8; 16]>), InvoiceError> {
    let result = watch.apply_inclusion(
        shard_id,
        height,
        output_idx,
        value_atoms,
        address,
        &mmr_proof_bytes,
        genesis_anchor,
    );
    if result == InclusionApplyResult::Accepted {
        let id = store.on_watch_inclusion(shard_id, height, output_idx, address, mmr_proof_bytes)?;
        return Ok((result, id));
    }
    Ok((result, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr_client::invoice::{InvoiceState, InvoiceStore};
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, InvoiceStore) {
        let dir = TempDir::new().unwrap();
        let store = InvoiceStore::open(dir.path()).unwrap();
        (dir, store)
    }

    // LC-47
    #[test]
    fn lc47_invalid_proof_rejected() {
        let mut watch = WatchNotifyState::default();
        let anchor = [0xABu8; 32];
        let r = watch.apply_inclusion(0, 100, 0, 500, [1u8; 32], b"not-a-proof", anchor);
        assert_eq!(r, InclusionApplyResult::InvalidProof);
        assert_eq!(watch.utxo_count(), 0);
    }

    // LC-46
    #[test]
    fn lc46_spent_notif_removes_utxo() {
        let mut watch = WatchNotifyState::default();
        watch.utxos.insert(
            (0, 10, 3),
            WatchUtxo {
                shard_id: 0,
                height: 10,
                output_idx: 3,
                value_atoms: 1,
                address: [2u8; 32],
            },
        );
        assert!(watch.apply_spent(0, 10, 3));
        assert_eq!(watch.utxo_count(), 0);
    }

    // LC-47b
    #[test]
    fn lc47b_pending_invoice_reorg_reverted() {
        let (_d, store) = temp_store();
        let addr = [0x55u8; 32];
        let id = store.create(addr, 100, 0, "", 0, 0).unwrap();
        store.on_watch_inclusion(0, 100, 0, addr, vec![1]).unwrap();

        let reverted = store.on_watch_revert(0, 100, 0).unwrap();
        assert_eq!(reverted, vec![id]);
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::ReorgReverted);
        assert_eq!(inv.height_hint, None);
        assert_eq!(inv.idx_hint, None);
    }

    // LC-47c / P0-2: Confirmed invoices revert the same as Pending.
    #[test]
    fn lc47c_confirmed_invoice_is_reverted() {
        let (_d, store) = temp_store();
        let addr = [0x66u8; 32];
        let id = store.create(addr, 100, 0, "", 0, 0).unwrap();
        store.on_watch_inclusion(0, 100, 0, addr, vec![1]).unwrap();
        store
            .advance_pending_confirmations(0, 100 + MIN_CONFIRMATION_DEPTH, MIN_CONFIRMATION_DEPTH)
            .unwrap();

        let reverted = store.on_watch_revert(0, 100, 0).unwrap();
        assert_eq!(reverted, vec![id]);
        let inv = store.load(&id).unwrap();
        assert_eq!(inv.state, InvoiceState::ReorgReverted);
        assert_eq!(inv.height_hint, None);
        assert_eq!(inv.idx_hint, None);
    }

    // LC-45
    #[test]
    fn lc45_pending_to_confirmed_at_depth_6() {
        let (_d, store) = temp_store();
        let addr = [0x77u8; 32];
        let id = store.create(addr, 100, 0, "", 0, 0).unwrap();
        store.on_watch_inclusion(0, 1000, 0, addr, vec![9]).unwrap();

        for tip in 1000..1000 + MIN_CONFIRMATION_DEPTH {
            let confirmed = store
                .advance_pending_confirmations(0, tip, MIN_CONFIRMATION_DEPTH)
                .unwrap();
            assert!(confirmed.is_empty(), "tip {tip} should stay pending");
            assert_eq!(
                store.load(&id).unwrap().state,
                InvoiceState::Pending((tip - 1000) as u8)
            );
        }

        let confirmed = store
            .advance_pending_confirmations(0, 1000 + MIN_CONFIRMATION_DEPTH, MIN_CONFIRMATION_DEPTH)
            .unwrap();
        assert_eq!(confirmed, vec![id]);
        assert_eq!(store.load(&id).unwrap().state, InvoiceState::Confirmed);
    }

    #[test]
    fn watch_registration_targets_dedup() {
        let (_d, store) = temp_store();
        let addr = [0x88u8; 32];
        let id1 = store.create(addr, 1, 0, "", 0, 0).unwrap();
        store.apply_hints(&id1, 1, 0, [0xCCu8; 32]).unwrap();
        store.create(addr, 2, 0, "", 0, 0).unwrap();
        let targets = store.watch_registration_targets().unwrap();
        assert_eq!(targets, vec![(addr, 0)]);
    }
}
