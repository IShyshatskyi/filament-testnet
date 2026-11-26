//! Epoch records as thin-sync data (Phase D, DYN-1): the exact active shard count of every
//! governance epoch, learned from beacon blocks Filament verified itself.
//!
//! Since NC-200 the first block of every governance epoch carries an epoch record (extension `0x0004`)
//! in its coinbase, and the proof-of-work covers it through the beacon body root. A Keystone serves
//! `GET /chain/epoch-record/{epoch}`: the block's header with a range proof into the beacon MMR, and
//! the record with its path under the header's body root ([`ThinEpochRecordResponse`]). Filament
//! checks the header's proof-of-work and its place in its own verified beacon chain, then the record
//! under the header's body root: the count is a fact of that block, not a Keystone's word.
//!
//! What it gives:
//! * **Dynamic shards** (DYN-1). A shard an expand vote opened is active from
//!   `epoch * epoch_length + activation_delay` of the first epoch whose record count exceeds its id
//!   ([`discover_dynamic_activation`]); the anchor then comes from the same header-proof route a genesis
//!   shard uses, and the shard is followed with the same checks. Counts only grow (an expand vote
//!   never shrinks the set), so the first such epoch is found by binary search.
//! * **The admissible range and `s_ref`** (V7, DAA-C1) for every followed shard, genesis ones included
//!   (`ThinShardParams::admissible_range`).
//!
//! Records are trusted only for epochs strictly before the beacon's current one: the block that starts
//! the current epoch may still be reorganised, an earlier one is buried by a whole epoch of work.

use network_common::common::proofs::ThinEpochRecordResponse;
use network_common::transaction::BeaconEpochRecord;

use crate::mmr_client::thin_chain::{ThinBeaconState, ThinSyncError};
use crate::mmr_client::thin_shard::{verified_headers, ThinShardParams};
use crate::mmr_client::thin_sync::fetch_json;

/// The record in `resp` for `epoch`, after every check described in the module doc.
pub fn verify_epoch_record(
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    epoch_length: u32,
    epoch: u32,
    resp: &ThinEpochRecordResponse,
) -> Result<BeaconEpochRecord, ThinSyncError> {
    let bad = |m: &str| ThinSyncError::BadResponse(m.to_string());
    if epoch == 0 || resp.epoch != epoch {
        return Err(bad("the response is not for the epoch asked"));
    }
    let height = epoch.checked_mul(epoch_length).ok_or_else(|| bad("epoch out of range"))?;
    let hs = verified_headers(beacon, bitcoin_anchor_hash, height, 1, &resp.header_proof)?;
    let record = resp
        .record_proof
        .verify(&hs[0].tx_merkle_root)
        .ok_or_else(|| bad("the epoch record does not verify under the header's beacon body root"))?;
    if record.epoch_index != epoch {
        return Err(bad("the record is for another epoch"));
    }
    Ok(record)
}

/// The newest epoch whose record Filament trusts: the one before the beacon's current epoch.
pub fn newest_trusted_epoch(beacon: &ThinBeaconState, epoch_length: u32) -> u32 {
    let tip = beacon.leaf_count().saturating_sub(1);
    (tip / epoch_length.max(1)).saturating_sub(1)
}

/// Fetch and verify one epoch's record from the first Keystone that gives a valid answer.
pub async fn fetch_epoch_record(
    http: &reqwest::Client,
    urls: &[String],
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    epoch_length: u32,
    epoch: u32,
) -> Result<BeaconEpochRecord, String> {
    let at = beacon.leaf_count();
    let mut last = String::from("no Keystone answered");
    for url in urls {
        let resp: Result<ThinEpochRecordResponse, String> =
            fetch_json(http, &format!("{url}/chain/epoch-record/{epoch}?at={at}")).await.map_err(|e| e.to_string());
        match resp.and_then(|r| verify_epoch_record(beacon, bitcoin_anchor_hash, epoch_length, epoch, &r).map_err(|e| e.to_string())) {
            Ok(rec) => return Ok(rec),
            Err(e) => last = format!("{url}: {e}"),
        }
    }
    Err(last)
}

fn insert_count(counts: &mut Vec<(u32, u16)>, epoch: u32, count: u16) {
    match counts.binary_search_by_key(&epoch, |(e, _)| *e) {
        Ok(i) => counts[i].1 = count,
        Err(i) => counts.insert(i, (epoch, count)),
    }
}

fn known(counts: &[(u32, u16)], epoch: u32) -> Option<u16> {
    counts.binary_search_by_key(&epoch, |(e, _)| *e).ok().map(|i| counts[i].1)
}

/// The count of `epoch` (>= 1): known, or fetched, verified and remembered in `counts`.
async fn count_of_epoch(
    http: &reqwest::Client,
    urls: &[String],
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    epoch_length: u32,
    counts: &mut Vec<(u32, u16)>,
    epoch: u32,
) -> Result<u16, String> {
    if let Some(c) = known(counts, epoch) {
        return Ok(c);
    }
    let rec = fetch_epoch_record(http, urls, beacon, bitcoin_anchor_hash, epoch_length, epoch).await?;
    insert_count(counts, epoch, rec.active_shard_count);
    Ok(rec.active_shard_count)
}

/// Make sure the counts the admissible range of a shard's blocks needs are verified: every epoch from
/// two before the shard's activation epoch up to [`newest_trusted_epoch`]. Fetches only what is
/// missing; stops at the first epoch no Keystone can prove (the caller retries next round).
pub async fn ensure_epoch_counts(
    http: &reqwest::Client,
    urls: &[String],
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    p: &ThinShardParams,
    counts: &mut Vec<(u32, u16)>,
) -> Result<(), String> {
    let Some(activation) = p.activation_height() else {
        return Ok(());
    };
    let newest = newest_trusted_epoch(beacon, p.epoch_length);
    let first = (activation / p.epoch_length.max(1)).saturating_sub(2).max(1);
    for epoch in first..=newest {
        count_of_epoch(http, urls, beacon, bitcoin_anchor_hash, p.epoch_length, counts, epoch).await?;
    }
    Ok(())
}

/// DYN-1: the beacon height at which dynamically activated shard `p.shard_id` becomes active, from
/// verified epoch records: `epoch * epoch_length + activation_delay` for the first epoch whose active
/// count exceeds the id. `Ok(None)` when no trusted epoch has opened it yet. Counts only grow, so the
/// first such epoch is found by binary search over the trusted epochs (`O(log epochs)` records).
pub async fn discover_dynamic_activation(
    http: &reqwest::Client,
    urls: &[String],
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    p: &ThinShardParams,
    counts: &mut Vec<(u32, u16)>,
) -> Result<Option<u32>, String> {
    debug_assert!(p.is_dynamic());
    let hi = newest_trusted_epoch(beacon, p.epoch_length);
    if hi < 1 {
        return Ok(None);
    }
    let opened = |c: u16| c > p.shard_id;
    if !opened(count_of_epoch(http, urls, beacon, bitcoin_anchor_hash, p.epoch_length, counts, hi).await?) {
        return Ok(None);
    }
    // Invariant: epoch `hi` has the shard open; `lo - 1` does not (epoch 0 is the genesis count,
    // which is `initial_shard_count <= shard_id`).
    let (mut lo, mut hi) = (1u32, hi);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if opened(count_of_epoch(http, urls, beacon, bitcoin_anchor_hash, p.epoch_length, counts, mid).await?) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(Some(lo.saturating_mul(p.epoch_length).saturating_add(p.activation_delay)))
}
