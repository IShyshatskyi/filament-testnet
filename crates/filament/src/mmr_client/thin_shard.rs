//! Thin shard chain state for the light client (`docs/plan/Filament_Thin_Sync_Design.md` §5).
//!
//! Same idea as [`ThinBeaconState`](crate::mmr_client::thin_chain::ThinBeaconState): MMR peaks, the
//! leaf count, the last [`RECENT_BLOCKS`] records, and a weight computed locally. What differs:
//!
//! * **The anchor.** A shard's MMR starts from the beacon root at the shard's activation block, not
//!   from the bitcoin anchor. Filament derives it from beacon data it verified itself
//!   ([`discover_anchor`]); it never takes it from a Keystone's word.
//! * **The work.** A shard block's proof-of-work sits in its auxiliary beacon header and its
//!   merged-mining sibling path, so a 136-byte header is not enough: every block arrives as a full
//!   [`FullShardBlockData`] record (~2.2 KB) and goes through the node's own
//!   `verify_shard_id_and_mmn` (target, rBits floor, hash-sorting route to *this* shard, sibling
//!   path to `merged_mining_root`). An empty sibling path is refused (the node accepts it only for
//!   test fixtures).
//!
//! Limits (stated, not hidden): the check covers the work a block claims, not that the claim equals
//! the shard DAA's expected difficulty; and the aux header's `committed_chain_count` is the miner's
//! claim, checked only against its own sibling path (Anti-Patterns #8/#17), not against the beacon's
//! epoch parameters. A cheap fake chain still has to be lighter than the real one and lose the
//! comparison between Keystones.

use std::collections::VecDeque;

use common_types::common::blocks::beacon_wire_header::WireBeaconHeader;
use common_types::common::blocks::shard_block::{Block, FullShardHeader};
use common_types::common::crypto::weighted_hash::{bag_peaks_weighted_u128, WeightedHash};
use common_types::common::genesis::genesis_config::{BeaconGenesisConfig, ShardGenesisConfig};
use common_types::common::blocks::shard_block::TxInclusionProof;
use common_types::common::proofs::{decode_shard_blocks, FullShardBlockData, ThinHeaderProofResponse, ThinShardBlocksResponse, ThinShardSessionResponse};
use common_types::common::validation::verify_shard_id_and_mmn;
use common_types::common::weighted_mmr_core::WeightedMMR;

use crate::mmr_client::thin_chain::{ThinBeaconState, ThinState, ThinSyncError};

/// How many full block records are kept (same as the beacon: owner decision, Oct 29, 2026).
pub const RECENT_BLOCKS: usize = 16;

/// Trusted facts a shard's checks need, all from the network's beacon genesis.
#[derive(Debug, Clone)]
pub struct ThinShardParams {
    pub shard_id: u16,
    pub initial_target: [u8; 32],
    pub genesis_asserted_s_bits: u32,
    pub tree_depth: usize,
    /// `shard_expansion.initial_shard_count`: shards below it exist from genesis.
    pub initial_shard_count: u16,
    /// Beacon blocks between genesis and a genesis shard's activation block.
    pub activation_delay: u32,
    pub shard_calibration: u32,
}

impl ThinShardParams {
    /// From the same trusted genesis source as the beacon facts.
    pub fn from_genesis(g: &BeaconGenesisConfig, shard_id: u16) -> Self {
        Self {
            shard_id,
            initial_target: g.max_target,
            genesis_asserted_s_bits: g.asserted_s_bits,
            tree_depth: g.tree_depth as usize,
            initial_shard_count: g.shard_expansion.initial_shard_count,
            activation_delay: g.shard_expansion.activation_delay,
            shard_calibration: g.shard_calibration,
        }
    }

    /// Beacon height of the activation block, for shards the genesis config lists.
    /// Dynamically activated shards need an expand-vote scan Filament does not do: `None`.
    pub fn activation_height(&self) -> Option<u32> {
        (self.shard_id < self.initial_shard_count).then_some(self.activation_delay)
    }
}

/// The two values a shard's chain is anchored to, derived from verified beacon data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAnchor {
    /// Beacon `current_mmr_root` at the activation height: the shard's genesis `prev_mmr_root`.
    pub root: WeightedHash,
    /// The height-0 shard block's required `difficulty`.
    pub genesis_bits: u32,
}

/// Anchor from the beacon state when it has just reached the activation block (the tip *is* it).
fn anchor_from_tip(beacon: &ThinBeaconState, p: &ThinShardParams) -> Option<ShardAnchor> {
    let tip = beacon.tip()?;
    (tip.height == p.activation_height()?).then(|| ShardAnchor {
        root: beacon.root(),
        genesis_bits: ShardGenesisConfig::bits_from_beacon_nbits(tip.bits, p.shard_calibration),
    })
}

/// Derive a shard's anchor from a header proof for the activation block and the block after it
/// (whose `prev_mmr_root` is the root *after* the activation block). The proof is checked against
/// the root of `beacon`, the quorum-trusted thin beacon state; nothing here is taken on trust.
pub fn anchor_from_header_proof(
    beacon: &ThinBeaconState,
    bitcoin_anchor_hash: [u8; 32],
    p: &ThinShardParams,
    resp: &ThinHeaderProofResponse,
) -> Result<ShardAnchor, ThinSyncError> {
    let bad = |m: &str| ThinSyncError::BadResponse(m.to_string());
    let a = p.activation_height().ok_or_else(|| bad("shard is not a genesis shard"))?;
    if resp.from != a {
        return Err(bad("header proof does not start at the activation height"));
    }
    let bytes = hex::decode(&resp.headers_hex).map_err(|_| bad("headers are not valid hex"))?;
    let hs: Vec<WireBeaconHeader> = bytes
        .chunks_exact(common_types::common::blocks::beacon_wire_header::WIRE_BEACON_HEADER_SIZE)
        .map(|c| WireBeaconHeader::deserialize(c).map_err(ThinSyncError::BadResponse))
        .collect::<Result<_, _>>()?;
    if hs.len() != 2 || bytes.len() != 2 * common_types::common::blocks::beacon_wire_header::WIRE_BEACON_HEADER_SIZE {
        return Err(bad("expected exactly the activation header and the one after"));
    }
    if hs[0].height != a || hs[1].height != a + 1 {
        return Err(bad("headers are not the activation block and its successor"));
    }
    let proof = &resp.range_proof;
    if proof.root != beacon.root() || proof.leaf_count != beacon.leaf_count() {
        return Err(bad("header proof is not against our verified beacon root"));
    }
    if proof.start != a || !proof.verify_with_anchor(bitcoin_anchor_hash) {
        return Err(bad("header proof does not verify against the anchor"));
    }
    for (i, h) in hs.iter().enumerate() {
        beacon.check_pow(h)?;
        let leaf = WeightedHash::from_leaf_rbits(&h.pow_hash(), h.bits);
        if proof.leaves.get(i) != Some(&leaf) {
            return Err(bad("a header does not match the proof's leaf"));
        }
    }
    Ok(ShardAnchor {
        root: hs[1].prev_mmr_root,
        genesis_bits: ShardGenesisConfig::bits_from_beacon_nbits(hs[0].bits, p.shard_calibration),
    })
}

/// Local-only part of anchor discovery: `Some` when the beacon tip is the activation block itself.
/// Otherwise the caller fetches a header proof (`GET /chain/header-proof/{a}?count=2&at=LEAVES`)
/// once the beacon is past it, and feeds it to [`anchor_from_header_proof`].
pub fn discover_anchor(beacon: &ThinBeaconState, p: &ThinShardParams) -> Option<ShardAnchor> {
    anchor_from_tip(beacon, p)
}

#[derive(Debug, Clone)]
pub struct ThinShardState {
    params: ThinShardParams,
    anchor: ShardAnchor,
    /// Bagging seed: the shard MMR is anchored at the activation root's 32 bytes.
    bag_anchor: WeightedHash,
    peaks: Vec<WeightedHash>,
    leaf_count: u32,
    root: WeightedHash,
    weight: u128,
    recent: VecDeque<FullShardBlockData>,
}

impl ThinShardState {
    pub fn new(params: ThinShardParams, anchor: ShardAnchor) -> Self {
        let bag_anchor = WeightedHash::from_anchor(&<[u8; 32]>::from(anchor.root));
        Self {
            params,
            anchor,
            bag_anchor,
            peaks: Vec::new(),
            leaf_count: 0,
            root: bag_anchor,
            weight: 0,
            recent: VecDeque::with_capacity(RECENT_BLOCKS),
        }
    }

    pub fn anchor(&self) -> ShardAnchor {
        self.anchor
    }

    pub fn tip(&self) -> Option<&FullShardBlockData> {
        self.recent.back()
    }

    pub fn recent(&self) -> impl Iterator<Item = &FullShardBlockData> {
        self.recent.iter()
    }

    /// Block hash (the header's own hash, as the node computes it) of a record.
    pub(crate) fn block_hash(&self, b: &FullShardBlockData) -> [u8; 32] {
        record_block_hash(self.params.shard_id, b)
    }

    pub fn peaks(&self) -> &[WeightedHash] {
        &self.peaks
    }

    /// Block hash of the tip.
    pub fn tip_hash(&self) -> Option<[u8; 32]> {
        self.recent.back().map(|b| self.block_hash(b))
    }

    /// MMR leaf of the block at `height`, when it is one of the held records.
    pub fn leaf_at(&self, height: u32) -> Option<WeightedHash> {
        let b = self.recent.iter().find(|b| b.height == height)?;
        Some(WeightedHash::from_leaf_rbits(&self.block_hash(b), b.difficulty))
    }

    /// The node's own shard checks on one record, without touching the state.
    fn check_work(&self, b: &FullShardBlockData) -> Result<[u8; 32], ThinSyncError> {
        if b.merged_mining_proof.is_empty() {
            return Err(ThinSyncError::BadPow("empty merged-mining sibling path"));
        }
        let header = FullShardHeader::new(
            b.height,
            b.prev_mmr_root,
            b.current_mmr_root,
            b.tx_merkle_root,
            b.difficulty,
            b.merged_mining_proof.clone(),
            self.params.shard_id,
            b.beacon_header.clone(),
        );
        let hash = header.hash();
        let block = Block::new(header, Vec::new());
        verify_shard_id_and_mmn(
            &block,
            self.params.tree_depth,
            b.beacon_header.committed_chain_count,
            None,
            &self.params.initial_target,
            self.params.genesis_asserted_s_bits,
        )
        .map_err(|_| ThinSyncError::BadPow("shard proof-of-work / hash-sorting / merged-mining check failed"))?;
        Ok(hash)
    }

    /// Verify `b` as the next block and append it. On error the state is unchanged.
    pub fn apply_block(&mut self, b: &FullShardBlockData) -> Result<(), ThinSyncError> {
        if b.height != self.leaf_count {
            return Err(ThinSyncError::WrongHeight { expected: self.leaf_count, got: b.height });
        }
        if b.height == 0 {
            if b.prev_mmr_root != self.anchor.root || b.difficulty != self.anchor.genesis_bits {
                return Err(ThinSyncError::PrevRootMismatch);
            }
        } else if b.prev_mmr_root != self.root {
            return Err(ThinSyncError::PrevRootMismatch);
        }
        let hash = self.check_work(b)?;
        let next_count = self.leaf_count.checked_add(1).ok_or(ThinSyncError::Overflow)?;
        let leaf = WeightedHash::from_leaf_rbits(&hash, b.difficulty);
        let (peaks, root, weight) =
            WeightedMMR::compute_peaks_after_append(&self.peaks, self.leaf_count, leaf, self.bag_anchor);
        if root != b.current_mmr_root {
            return Err(ThinSyncError::BadResponse("current_mmr_root does not match the locally computed root".into()));
        }
        self.peaks = peaks;
        self.root = root;
        self.weight = weight;
        self.leaf_count = next_count;
        if self.recent.len() == RECENT_BLOCKS {
            self.recent.pop_front();
        }
        self.recent.push_back(b.clone());
        Ok(())
    }

    /// Apply consecutive records from an incremental response, stopping at the first
    /// failure. Returns how many were applied.
    pub fn apply_blocks_hex(&mut self, blocks_hex: &str) -> Result<usize, (usize, ThinSyncError)> {
        let blocks = decode_shard_blocks(blocks_hex).map_err(|e| (0, ThinSyncError::BadResponse(e)))?;
        for (i, b) in blocks.iter().enumerate() {
            self.apply_block(b).map_err(|e| (i, e))?;
        }
        Ok(blocks.len())
    }

    /// Build the state from a session response. A session that starts at height 0 is replayed
    /// from the anchor, block by block. Otherwise the range proof's peaks must bag to its root and
    /// chain back to the anchor, and every record's PoW-valid leaf must equal the proof's leaf at
    /// that index. The records must link (`next.prev_mmr_root == this.current_mmr_root`) and the
    /// last one must end at the proof root: `current_mmr_root` is not part of a block's hash, so
    /// the links are what pin it. The weight comes from the proven peaks, not from the wire.
    pub fn from_session(
        params: ThinShardParams,
        anchor: ShardAnchor,
        resp: &ThinShardSessionResponse,
    ) -> Result<Self, ThinSyncError> {
        let bad = |m: &str| ThinSyncError::BadResponse(m.to_string());
        let blocks = decode_shard_blocks(&resp.blocks_hex).map_err(ThinSyncError::BadResponse)?;
        if blocks.is_empty() {
            return Err(bad("no blocks"));
        }
        let n = blocks.len() as u32;
        let first = resp.leaf_count.checked_sub(n).ok_or_else(|| bad("more blocks than leaves"))?;
        for (i, b) in blocks.iter().enumerate() {
            if b.height != first + i as u32 {
                return Err(bad("blocks are not consecutive up to the tip"));
            }
        }
        let mut st = Self::new(params, anchor);
        if first == 0 {
            for b in &blocks {
                st.apply_block(b)?;
            }
            if hex::encode(<[u8; 32]>::from(st.root)) != resp.root_hex {
                return Err(bad("response root differs from the replayed root"));
            }
            return Ok(st);
        }
        let Some(proof) = &resp.range_proof else {
            return Err(bad("a proof is required when the session does not start at height 0"));
        };
        if proof.leaf_count != resp.leaf_count || proof.end != resp.leaf_count {
            return Err(bad("proof does not end at the response's leaf count"));
        }
        if hex::encode(<[u8; 32]>::from(proof.root)) != resp.root_hex {
            return Err(bad("response root differs from the proof root"));
        }
        if !proof.verify_with_anchor(<[u8; 32]>::from(anchor.root)) {
            return Err(bad("range proof does not verify against the anchor"));
        }
        if first > proof.start {
            return Err(bad("blocks do not cover the proof range"));
        }
        for b in blocks.iter().filter(|b| b.height >= proof.start) {
            let hash = st.check_work(b)?;
            let idx = (b.height - proof.start) as usize;
            let leaf = WeightedHash::from_leaf_rbits(&hash, b.difficulty);
            if proof.leaves.get(idx) != Some(&leaf) {
                return Err(bad("a block does not match the proof's leaf"));
            }
        }
        for w in blocks.windows(2) {
            if w[1].prev_mmr_root != w[0].current_mmr_root {
                return Err(bad("blocks do not link by their MMR roots"));
            }
        }
        if blocks.last().map(|b| b.current_mmr_root) != Some(proof.root) {
            return Err(bad("the last block does not end at the proof root"));
        }
        st.weight = bag_peaks_weighted_u128(&proof.peaks, st.bag_anchor).1;
        st.peaks = proof.peaks.clone();
        st.leaf_count = resp.leaf_count;
        st.root = proof.root;
        let keep = blocks.len().saturating_sub(RECENT_BLOCKS);
        st.recent = blocks.into_iter().skip(keep).collect();
        Ok(st)
    }
}

/// Result of tying a payment's inclusion proof to Filament's own verified shard chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// The block that paid is the block at that height in the chain Filament verified itself.
    Bound,
    /// Not shown (yet): why. Retry on a later round.
    Unbound(String),
}

/// Design §6: an invoice may be confirmed only when the block that paid it is in the chain
/// Filament verified with its own proof-of-work checks and quorum, not merely in a chain some
/// Keystone proved to itself. The inclusion notification's batch proof gives the leaf of the
/// paying block at `height`; this checks that leaf against `st`:
///
/// * the proof verifies against the shard anchor (it is a proof about this shard's MMR);
/// * if `height` is one of the records `st` holds, the leaf recomputed from the record equals it;
/// * otherwise a fresh range proof for `height` from a Keystone must verify against the anchor,
///   end at exactly `st`'s root and leaf count (a proof for any other root is ignored), and carry
///   the same leaf. Height 0 has no range proof (the genesis leaf is excluded), so it binds only
///   while it is a held record.
///
/// The Keystone is asked for a proof, never for a verdict: a lying or lagging one just fails to bind.
pub async fn bind_inclusion(
    http: &reqwest::Client,
    endpoints: &[String],
    st: &ThinShardState,
    shard_id: u16,
    height: u32,
    notif_proof_bytes: &[u8],
) -> Binding {
    use common_types::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};
    let anchor = <[u8; 32]>::from(st.anchor().root);
    let Ok((proof, _)) = bincode::serde::decode_from_slice::<WeightedMMRBatchProof, _>(
        notif_proof_bytes,
        bincode::config::standard(),
    ) else {
        return Binding::Unbound("the stored inclusion proof does not decode".into());
    };
    if !proof.verify_with_anchor(anchor) {
        return Binding::Unbound("the inclusion proof does not verify against the shard anchor".into());
    }
    let Some(pos) = proof.leaf_indices.iter().position(|&i| i == height) else {
        return Binding::Unbound("the inclusion proof does not cover the paying block".into());
    };
    let claimed = proof.leaf_hashes[pos];
    if height >= st.leaf_count() {
        return Binding::Unbound("the paying block is above our verified tip".into());
    }
    if let Some(local) = st.leaf_at(height) {
        return if local == claimed {
            Binding::Bound
        } else {
            Binding::Unbound("the paying block is not the block in our verified chain".into())
        };
    }
    if height == 0 {
        return Binding::Unbound("the genesis block can only be bound while it is a held record".into());
    }
    let mut last = String::from("no Keystone answered");
    for ep in endpoints {
        let url = format!("{ep}/shard/{shard_id}/chain/range/{height}/{height}");
        let range: WeightedMMRRangeProof = match crate::mmr_client::thin_sync::fetch_json(http, &url).await {
            Ok(r) => r,
            Err(e) => {
                last = format!("{ep}: {e}");
                continue;
            }
        };
        if range.root != st.root() || range.leaf_count != st.leaf_count() {
            last = format!("{ep}: its proof is for another root than ours");
            continue;
        }
        if range.start != height || range.leaves.len() != 1 || !range.verify_with_anchor(anchor) {
            last = format!("{ep}: its proof does not verify");
            continue;
        }
        return if range.leaves[0] == claimed {
            Binding::Bound
        } else {
            Binding::Unbound("the paying block is not the block in our verified chain".into())
        };
    }
    Binding::Unbound(last)
}

/// A shard block record's own block hash, as the node computes it.
pub(crate) fn record_block_hash(shard_id: u16, b: &FullShardBlockData) -> [u8; 32] {
    FullShardHeader::new(
        b.height,
        b.prev_mmr_root,
        b.current_mmr_root,
        b.tx_merkle_root,
        b.difficulty,
        b.merged_mining_proof.clone(),
        shard_id,
        b.beacon_header.clone(),
    )
    .hash()
}

/// The leaf the stored inclusion notification's batch proof claims for `height`.
fn notif_leaf(notif_proof_bytes: &[u8], height: u32) -> Option<WeightedHash> {
    use common_types::common::proofs::WeightedMMRBatchProof;
    let (proof, _): (WeightedMMRBatchProof, usize) =
        bincode::serde::decode_from_slice(notif_proof_bytes, bincode::config::standard()).ok()?;
    let pos = proof.leaf_indices.iter().position(|&i| i == height)?;
    proof.leaf_hashes.get(pos).copied()
}

/// Design §6, the part that ties the *payment* to the block: `proof` must show that the output at
/// `output_idx` of the block at `height` is committed by `tx_merkle_root` (the root in a block
/// record already bound to Filament's verified chain), and that output must pay `recipient` at
/// least `amount_atoms` (0 = any amount). Pure; no network.
pub fn check_payment(
    tx_merkle_root: &[u8; 32],
    proof: &TxInclusionProof,
    height: u32,
    output_idx: u16,
    recipient: &[u8; 32],
    amount_atoms: u64,
) -> Result<(), String> {
    if proof.height != height || proof.output_idx != u32::from(output_idx) {
        return Err("the proof is for another output".into());
    }
    if !proof.verify(tx_merkle_root) {
        return Err("the proof does not verify against the block's tx_merkle_root".into());
    }
    let out = proof.output().ok_or_else(|| "the proof carries no such output".to_string())?;
    if &out.recipient != recipient {
        return Err("the output does not pay the invoice's recipient".into());
    }
    if out.value < amount_atoms {
        return Err(format!("the output pays {} atoms, the invoice asks {}", out.value, amount_atoms));
    }
    Ok(())
}

/// [`bind_inclusion`] plus the payment itself: the paying block's record (held, or fetched and
/// checked to hash to the very leaf the verified chain holds) supplies `tx_merkle_root`; a Keystone
/// is then asked for a [`TxInclusionProof`] of the output, which Filament verifies and compares
/// with the invoice. A Keystone's notification alone (`height`, `output_idx`, value, address) is
/// never enough: a lying one could name any real block.
#[allow(clippy::too_many_arguments)]
pub async fn bind_payment(
    http: &reqwest::Client,
    endpoints: &[String],
    st: &ThinShardState,
    shard_id: u16,
    height: u32,
    output_idx: u16,
    recipient: &[u8; 32],
    amount_atoms: u64,
    notif_proof_bytes: &[u8],
) -> Binding {
    match bind_inclusion(http, endpoints, st, shard_id, height, notif_proof_bytes).await {
        Binding::Bound => {}
        other => return other,
    }
    // The block record whose hash is the verified chain's leaf at `height`.
    let root = if let Some(b) = st.recent().find(|b| b.height == height) {
        b.tx_merkle_root
    } else {
        let Some(claimed) = notif_leaf(notif_proof_bytes, height) else {
            return Binding::Unbound("the stored inclusion proof does not cover the paying block".into());
        };
        let mut last = String::from("no Keystone answered");
        let mut found = None;
        for ep in endpoints {
            let url = format!("{ep}/shard/{shard_id}/chain/headers/{height}?max=1");
            let resp: ThinShardBlocksResponse = match crate::mmr_client::thin_sync::fetch_json(http, &url).await {
                Ok(r) => r,
                Err(e) => {
                    last = format!("{ep}: {e}");
                    continue;
                }
            };
            let rec = match decode_shard_blocks(&resp.blocks_hex).map(|mut v| v.drain(..).find(|b| b.height == height)) {
                Ok(Some(r)) => r,
                _ => {
                    last = format!("{ep}: no block record for height {height}");
                    continue;
                }
            };
            if WeightedHash::from_leaf_rbits(&st.block_hash(&rec), rec.difficulty) != claimed {
                last = format!("{ep}: its block record is not the block in our verified chain");
                continue;
            }
            found = Some(rec.tx_merkle_root);
            break;
        }
        match found {
            Some(r) => r,
            None => return Binding::Unbound(last),
        }
    };
    let mut last = String::from("no Keystone answered");
    for ep in endpoints {
        let url = format!("{ep}/shard/{shard_id}/tx-proof?height={height}&output_idx={output_idx}");
        let proof: TxInclusionProof = match crate::mmr_client::thin_sync::fetch_json(http, &url).await {
            Ok(p) => p,
            Err(e) => {
                last = format!("{ep}: {e}");
                continue;
            }
        };
        match check_payment(&root, &proof, height, output_idx, recipient, amount_atoms) {
            Ok(()) => return Binding::Bound,
            Err(e) => last = format!("{ep}: {e}"),
        }
    }
    Binding::Unbound(last)
}

/// Lower-assurance payment check for a shard Filament has no verified chain for (a dynamically
/// activated shard: its activation cannot be derived from verified headers, see the design doc).
/// Each Keystone is asked for the block record at `height` and a [`TxInclusionProof`] of the
/// output; a Keystone counts only if its proof verifies against its own record's
/// `tx_merkle_root` and pays the invoice. The payment is `Bound` when at least `required`
/// distinct Keystones agree on the same block hash. One Keystone can no longer name a block or
/// forge an output; `required` colluding ones still can, which is why the invoice is labelled
/// [`crate::mmr_client::invoice::ASSURANCE_KEYSTONE_QUORUM`].
#[allow(clippy::too_many_arguments)]
pub async fn quorum_payment(
    http: &reqwest::Client,
    endpoints: &[String],
    shard_id: u16,
    height: u32,
    output_idx: u16,
    recipient: &[u8; 32],
    amount_atoms: u64,
    required: usize,
) -> Binding {
    use std::collections::HashMap;
    let mut agree: HashMap<[u8; 32], usize> = HashMap::new();
    let mut last = String::from("no Keystone answered");
    for ep in endpoints {
        let url = format!("{ep}/shard/{shard_id}/chain/headers/{height}?max=1");
        let resp: ThinShardBlocksResponse = match crate::mmr_client::thin_sync::fetch_json(http, &url).await {
            Ok(r) => r,
            Err(e) => {
                last = format!("{ep}: {e}");
                continue;
            }
        };
        let Some(rec) = decode_shard_blocks(&resp.blocks_hex).ok().and_then(|v| v.into_iter().find(|b| b.height == height)) else {
            last = format!("{ep}: no block record for height {height}");
            continue;
        };
        let url = format!("{ep}/shard/{shard_id}/tx-proof?height={height}&output_idx={output_idx}");
        let proof: TxInclusionProof = match crate::mmr_client::thin_sync::fetch_json(http, &url).await {
            Ok(p) => p,
            Err(e) => {
                last = format!("{ep}: {e}");
                continue;
            }
        };
        match check_payment(&rec.tx_merkle_root, &proof, height, output_idx, recipient, amount_atoms) {
            Ok(()) => *agree.entry(record_block_hash(shard_id, &rec)).or_insert(0) += 1,
            Err(e) => last = format!("{ep}: {e}"),
        }
    }
    if agree.values().any(|&n| n >= required.max(1)) {
        Binding::Bound
    } else {
        Binding::Unbound(format!("fewer than {} Keystones prove this payment ({last})", required.max(1)))
    }
}

impl ThinState for ThinShardState {
    fn leaf_count(&self) -> u32 {
        self.leaf_count
    }
    fn root(&self) -> WeightedHash {
        self.root
    }
    fn weight(&self) -> u128 {
        self.weight
    }
    fn prev_root_at(&self, height: u32) -> Option<WeightedHash> {
        self.recent.iter().find(|b| b.height == height).map(|b| b.prev_mmr_root)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mmr_client::thin_chain::tests::{build_proving, ANCHOR};
    use common_types::common::blocks::shard_block::BeaconHeader;
    use common_types::common::crypto::merged_mining_hash::MergedMiningHash;
    use common_types::common::crypto::weighted_hash::u128_to_rbits;
    use common_types::common::proofs::{encode_shard_blocks, ThinHeaderProofResponse};
    use common_types::common::windowed_weighted_mmr::WindowedWeightedMMR;

    /// Soft target so a nonce is found in a few thousand probes (the node's own tests do the same).
    pub(crate) fn soft_target() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[1] = 0xff;
        t
    }

    pub(crate) fn test_params(shard_id: u16) -> ThinShardParams {
        ThinShardParams {
            shard_id,
            initial_target: soft_target(),
            genesis_asserted_s_bits: 1,
            tree_depth: 2,
            initial_shard_count: 3,
            activation_delay: 4,
            shard_calibration: 16,
        }
    }

    /// D = 4 meets the floor `2^asserted_s` for three committed chains (s = 2).
    pub(crate) fn test_anchor() -> ShardAnchor {
        ShardAnchor { root: WeightedHash::from([5u8; 32]), genesis_bits: u128_to_rbits(4) }
    }

    /// Mine the next shard block: a merged-mining tree of three active shards (the block's own
    /// leaf in its slot, random-looking siblings elsewhere) and a nonce whose hash passes the
    /// node's own `verify_shard_id_and_mmn` for `shard_id`.
    pub(crate) fn mine_block(
        shard_id: u16,
        height: u32,
        prev: WeightedHash,
        difficulty: u32,
        salt: u8,
    ) -> FullShardBlockData {
        let tx = body_at(height, salt).calculate_tx_merkle_root();
        let leaf = FullShardHeader::new(
            height,
            prev,
            WeightedHash::zero(),
            tx,
            difficulty,
            vec![],
            shard_id,
            BeaconHeader::new(1, 0, 0, WeightedHash::zero(), [0; 32], 0x0300_0001, 0, 0, [0; 32]),
        )
        .merged_mining_leaf_hash();
        // Four leaves: shards 0..=2 active, slot 3 empty (three active chains).
        let mut leaves: Vec<MergedMiningHash> = (0..4u8)
            .map(|i| if i < 3 { MergedMiningHash::from_active_leaf(&[i + 40 + salt; 32]) } else { MergedMiningHash::from_empty_leaf() })
            .collect();
        leaves[shard_id as usize] = MergedMiningHash::from_active_leaf(&leaf);
        let proof = vec![
            leaves[(shard_id ^ 1) as usize],
            if shard_id < 2 {
                MergedMiningHash::combine(&leaves[2], &leaves[3])
            } else {
                MergedMiningHash::combine(&leaves[0], &leaves[1])
            },
        ];
        let l01 = MergedMiningHash::combine(&leaves[0], &leaves[1]);
        let l23 = MergedMiningHash::combine(&leaves[2], &leaves[3]);
        let root = *MergedMiningHash::combine(&l01, &l23).raw();

        let mut bh = BeaconHeader::new(1, 1_704_067_200, 0, WeightedHash::zero(), root, 0x0300_0001, 1_704_067_200, 0, [0; 32]);
        bh.committed_chain_count = 3;
        loop {
            let header = FullShardHeader::new(
                height,
                prev,
                WeightedHash::zero(),
                tx,
                difficulty,
                proof.clone(),
                shard_id,
                bh.clone(),
            );
            let block = Block::new(header, Vec::new());
            if verify_shard_id_and_mmn(&block, 2, 3, None, &soft_target(), 1).is_ok() {
                return FullShardBlockData {
                    height,
                    prev_mmr_root: prev,
                    current_mmr_root: WeightedHash::zero(), // set by the chain builder
                    tx_merkle_root: tx,
                    difficulty,
                    chain_weight: 0,
                    beacon_header: bh,
                    merged_mining_proof: proof,
                };
            }
            bh.nonce += 1;
        }
    }

    /// Who block `height` pays (its single output).
    pub(crate) fn payee_at(height: u32, salt: u8) -> [u8; 32] {
        [height as u8 ^ salt ^ 0x55; 32]
    }

    /// The body of the test block at `height`: one coinbase-like transaction paying
    /// [`payee_at`] 1,000 atoms. Its root is the block's real `tx_merkle_root`.
    pub(crate) fn body_at(height: u32, salt: u8) -> common_types::common::blocks::shard_block::ShardBlockBody {
        use common_types::transaction::{FlatOutput, TransactionDescriptor};
        let mut b = common_types::common::blocks::shard_block::ShardBlockBody::default();
        b.outputs.push(FlatOutput { value: 1_000, recipient: payee_at(height, salt) });
        b.descriptors.push(TransactionDescriptor {
            out_start: 0, out_len: 1, in_start: 0, in_len: 0,
            witness_start: 0, witness_len: 0, extension_start: 0, extension_len: 0,
        });
        b
    }

    /// A valid shard chain, with the real MMR implementations that serve its proofs.
    pub(crate) struct Chain {
        pub(crate) blocks: Vec<FullShardBlockData>,
        pub(crate) core: WeightedMMR,
        pub(crate) win: WindowedWeightedMMR,
        pub(crate) shard_id: u16,
        pub(crate) salt: u8,
        pub(crate) anchor: ShardAnchor,
    }

    impl Chain {
        pub(crate) fn body_at(&self, height: u32) -> common_types::common::blocks::shard_block::ShardBlockBody {
            body_at(height, self.salt)
        }

        pub(crate) fn payee(&self, height: u32) -> [u8; 32] {
            payee_at(height, self.salt)
        }

        pub(crate) fn new(shard_id: u16, salt: u8) -> Self {
            Self::new_anchored(shard_id, salt, test_anchor())
        }

        pub(crate) fn new_anchored(shard_id: u16, salt: u8, anchor: ShardAnchor) -> Self {
            let anchor_bytes = <[u8; 32]>::from(anchor.root);
            let mut cfg = common_types::common::genesis::genesis_config::BeaconGenesisConfig::devnet();
            cfg.bitcoin_anchor_hash = anchor_bytes;
            Self {
                blocks: Vec::new(),
                core: WeightedMMR::with_anchor_and_capacity(anchor_bytes, 64),
                win: WindowedWeightedMMR::new(&cfg),
                shard_id,
                salt,
                anchor,
            }
        }

        pub(crate) fn with_anchor_len(shard_id: u16, salt: u8, anchor: ShardAnchor, n: u32) -> Self {
            let mut c = Self::new_anchored(shard_id, salt, anchor);
            c.extend(n);
            c
        }

        pub(crate) fn with_len(shard_id: u16, salt: u8, n: u32) -> Self {
            let mut c = Self::new(shard_id, salt);
            c.extend(n);
            c
        }

        pub(crate) fn extend(&mut self, k: u32) {
            for _ in 0..k {
                let height = self.blocks.len() as u32;
                let prev = if height == 0 { self.anchor.root } else { self.core.get_root() };
                let difficulty = self.anchor.genesis_bits;
                let mut b = mine_block(self.shard_id, height, prev, difficulty, self.salt);
                let hash = FullShardHeader::new(
                    b.height,
                    b.prev_mmr_root,
                    b.current_mmr_root,
                    b.tx_merkle_root,
                    b.difficulty,
                    b.merged_mining_proof.clone(),
                    self.shard_id,
                    b.beacon_header.clone(),
                )
                .hash();
                let leaf = WeightedHash::from_leaf_rbits(&hash, b.difficulty);
                let (root, _) = self.core.append(leaf);
                self.win.append(leaf).unwrap();
                b.current_mmr_root = root;
                self.blocks.push(b);
            }
        }

        pub(crate) fn session(&self, k: usize) -> ThinShardSessionResponse {
            let n = self.blocks.len() as u32;
            let k = k.min(self.blocks.len());
            let first = n - k as u32;
            ThinShardSessionResponse {
                leaf_count: n,
                root_hex: hex::encode(self.win.get_root_bytes()),
                blocks_hex: encode_shard_blocks(&self.blocks[self.blocks.len() - k..]).unwrap(),
                range_proof: (first >= 1).then(|| self.win.prove_range(first, n).unwrap()),
            }
        }
    }

    fn fresh() -> ThinShardState {
        ThinShardState::new(test_params(0), test_anchor())
    }

    #[test]
    fn matches_the_real_mmr_root_and_weight_at_every_height() {
        let c = Chain::with_len(0, 0, 25);
        let mut mmr = WeightedMMR::with_anchor_and_capacity(<[u8; 32]>::from(test_anchor().root), 64);
        let mut st = fresh();
        for b in &c.blocks {
            let hash = FullShardHeader::new(
                b.height, b.prev_mmr_root, b.current_mmr_root, b.tx_merkle_root, b.difficulty,
                b.merged_mining_proof.clone(), 0, b.beacon_header.clone(),
            )
            .hash();
            let (root, weight) = mmr.append(WeightedHash::from_leaf_rbits(&hash, b.difficulty));
            st.apply_block(b).unwrap_or_else(|e| panic!("height {}: {e}", b.height));
            assert_eq!((st.root(), st.weight()), (root, weight), "height {}", b.height);
        }
        assert_eq!(st.recent().count(), RECENT_BLOCKS);
        assert_eq!(st.tip().unwrap().height, 24);
    }

    #[test]
    fn a_long_session_start_matches_replaying_every_block() {
        let c = Chain::with_len(0, 0, 40);
        let st = ThinShardState::from_session(test_params(0), test_anchor(), &c.session(16)).unwrap();
        let mut replay = fresh();
        for b in &c.blocks {
            replay.apply_block(b).unwrap();
        }
        assert_eq!((st.root(), st.weight(), st.leaf_count()), (replay.root(), replay.weight(), 40));
        assert_eq!(st.peaks(), replay.peaks());
        assert_eq!(st.recent().map(|b| b.height).collect::<Vec<_>>(), (24..40).collect::<Vec<_>>());
    }

    #[test]
    fn a_short_chain_session_is_replayed_from_the_anchor_without_a_proof() {
        let c = Chain::with_len(0, 0, 9);
        let resp = c.session(16);
        assert!(resp.range_proof.is_none(), "starts at height 0: nothing to prove");
        let st = ThinShardState::from_session(test_params(0), test_anchor(), &resp).unwrap();
        assert_eq!((st.leaf_count(), st.root()), (9, c.core.get_root()));
    }

    #[test]
    fn rejects_a_block_routed_to_another_shard() {
        // Mined for shard 1, offered to a thin state for shard 0: hash-sorting sends it elsewhere.
        let c = Chain::with_len(1, 0, 1);
        let mut st = fresh();
        assert!(matches!(st.apply_block(&c.blocks[0]), Err(ThinSyncError::BadPow(_))));
        assert_eq!(st.leaf_count(), 0);
        // And the same block is fine for shard 1.
        let mut st1 = ThinShardState::new(test_params(1), test_anchor());
        st1.apply_block(&c.blocks[0]).unwrap();
    }

    #[test]
    fn rejects_an_empty_sibling_path_and_a_broken_nonce() {
        let c = Chain::with_len(0, 0, 2);
        let mut st = fresh();
        let mut no_path = c.blocks[0].clone();
        no_path.merged_mining_proof.clear();
        assert!(matches!(st.apply_block(&no_path), Err(ThinSyncError::BadPow(_))));
        let mut wrong_nonce = c.blocks[0].clone();
        wrong_nonce.beacon_header.nonce ^= 0xFFFF_FFFF;
        assert!(st.apply_block(&wrong_nonce).is_err());
        let mut wrong_root = c.blocks[0].clone();
        wrong_root.beacon_header.merged_mining_root[0] ^= 1;
        assert!(st.apply_block(&wrong_root).is_err());
        assert_eq!(st.leaf_count(), 0, "failed applies leave the state unchanged");
        st.apply_block(&c.blocks[0]).unwrap();
    }

    #[test]
    fn rejects_a_wrong_genesis_link_wrong_genesis_bits_gap_and_bad_root() {
        let c = Chain::with_len(0, 0, 4);
        // Genesis must link to the anchor and carry the derived difficulty.
        let other_anchor = ShardAnchor { root: WeightedHash::from([6u8; 32]), ..test_anchor() };
        assert_eq!(
            ThinShardState::new(test_params(0), other_anchor).apply_block(&c.blocks[0]),
            Err(ThinSyncError::PrevRootMismatch)
        );
        let other_bits = ShardAnchor { genesis_bits: u128_to_rbits(8), ..test_anchor() };
        assert_eq!(
            ThinShardState::new(test_params(0), other_bits).apply_block(&c.blocks[0]),
            Err(ThinSyncError::PrevRootMismatch)
        );
        let mut st = fresh();
        st.apply_block(&c.blocks[0]).unwrap();
        assert_eq!(st.apply_block(&c.blocks[2]), Err(ThinSyncError::WrongHeight { expected: 1, got: 2 }));
        // `current_mmr_root` is not part of the block hash, but the state checks it against its own root.
        let mut lying = c.blocks[1].clone();
        lying.current_mmr_root = WeightedHash::from([9u8; 32]);
        assert!(matches!(st.apply_block(&lying), Err(ThinSyncError::BadResponse(_))));
        st.apply_block(&c.blocks[1]).unwrap();
    }

    #[test]
    fn a_session_with_a_tampered_block_or_root_is_rejected() {
        let c = Chain::with_len(0, 0, 40);
        let ok = c.session(16);
        ThinShardState::from_session(test_params(0), test_anchor(), &ok).unwrap();

        let mut bad_root = ok.clone();
        bad_root.root_hex = hex::encode([0x42u8; 32]);
        assert!(ThinShardState::from_session(test_params(0), test_anchor(), &bad_root).is_err());

        let mut bad_count = ok.clone();
        bad_count.leaf_count += 1;
        assert!(ThinShardState::from_session(test_params(0), test_anchor(), &bad_count).is_err());

        // A block from another valid chain in the middle: its leaf is not the proof's leaf.
        let other = Chain::with_len(0, 1, 40);
        let mut blocks = common_types::common::proofs::decode_shard_blocks(&ok.blocks_hex).unwrap();
        blocks[5] = other.blocks[29].clone();
        let mut swapped = ok.clone();
        swapped.blocks_hex = encode_shard_blocks(&blocks).unwrap();
        assert!(ThinShardState::from_session(test_params(0), test_anchor(), &swapped).is_err());

        // A forged `current_mmr_root` between two honest blocks breaks the link check.
        let mut blocks = common_types::common::proofs::decode_shard_blocks(&ok.blocks_hex).unwrap();
        blocks[5].current_mmr_root = WeightedHash::from([1u8; 32]);
        let mut forged = ok.clone();
        forged.blocks_hex = encode_shard_blocks(&blocks).unwrap();
        assert!(ThinShardState::from_session(test_params(0), test_anchor(), &forged).is_err());

        // A proof is required once the session does not start at height 0.
        let mut no_proof = ok;
        no_proof.range_proof = None;
        assert!(ThinShardState::from_session(test_params(0), test_anchor(), &no_proof).is_err());
    }

    /// Prints the shard wire sizes for a real mined block with a depth-2 sibling path (JSON bytes).
    /// Every extra tree level adds one 32-byte sibling = 64 hex characters to each record.
    #[test]
    fn wire_sizes_with_a_real_sibling_path() {
        let c = Chain::with_len(0, 0, 40);
        let session = serde_json::to_vec(&c.session(16)).unwrap().len();
        let one = serde_json::to_vec(&common_types::common::proofs::ThinShardBlocksResponse {
            from: 39,
            leaf_count: 40,
            blocks_hex: encode_shard_blocks(&c.blocks[39..]).unwrap(),
        })
        .unwrap()
        .len();
        let record = bincode::serde::encode_to_vec(&c.blocks[39], bincode::config::standard()).unwrap().len();
        eprintln!("shard record {record} B binary; session (16 records + range proof) {session} B; one new block {one} B");
        assert!(one < 1000 && session < 40_000);
    }

    // ── anchor discovery from verified beacon data ───────────────────────────

    fn beacon_state(n: u32) -> (ThinBeaconState, Vec<WireBeaconHeader>, WindowedWeightedMMR) {
        let (hs, win) = build_proving(n);
        let resp = crate::mmr_client::thin_chain::tests::session(&hs, &win, 16);
        (ThinBeaconState::from_session(ANCHOR, [0xFF; 32], 1, &resp).unwrap(), hs, win)
    }

    fn header_proof(hs: &[WireBeaconHeader], win: &WindowedWeightedMMR, from: u32) -> ThinHeaderProofResponse {
        let n = hs.len() as u32;
        ThinHeaderProofResponse {
            from,
            leaf_count: n,
            root_hex: hex::encode(win.get_root_bytes()),
            headers_hex: hex::encode(hs[from as usize..from as usize + 2].iter().flat_map(|h| h.serialize()).collect::<Vec<u8>>()),
            range_proof: win.prove_range(from, from + 2).unwrap_or_else(|_| win.prove_range(from, n).unwrap()),
        }
    }

    #[test]
    fn the_anchor_is_the_beacon_root_after_the_activation_block() {
        let (beacon, hs, win) = beacon_state(60);
        let p = test_params(0); // activation height 4
        let anchor = anchor_from_header_proof(&beacon, ANCHOR, &p, &header_proof(&hs, &win, 4)).unwrap();
        // The root after block 4 = a chain of five leaves.
        let mut replay = ThinBeaconState::new(ANCHOR, [0xFF; 32], 1);
        for h in &hs[..5] {
            replay.apply_header(h).unwrap();
        }
        assert_eq!(anchor.root, replay.root());
        assert_eq!(anchor.genesis_bits, ShardGenesisConfig::bits_from_beacon_nbits(hs[4].bits, 16));
    }

    #[test]
    fn an_anchor_proof_is_refused_when_it_is_not_ours() {
        let (beacon, hs, win) = beacon_state(60);
        let p = test_params(0);
        let ok = header_proof(&hs, &win, 4);
        // Wrong start.
        let mut wrong_from = ok.clone();
        wrong_from.from = 5;
        assert!(anchor_from_header_proof(&beacon, ANCHOR, &p, &wrong_from).is_err());
        // Headers that do not match the proven leaves.
        let mut swapped = ok.clone();
        swapped.headers_hex = hex::encode(hs[10..12].iter().flat_map(|h| h.serialize()).collect::<Vec<u8>>());
        assert!(anchor_from_header_proof(&beacon, ANCHOR, &p, &swapped).is_err());
        // A proof against a different chain's root.
        let (_, other_win) = crate::mmr_client::thin_chain::tests::build_proving_salted(60, 1);
        let (other_hs, _) = crate::mmr_client::thin_chain::tests::build_proving_salted(60, 1);
        let foreign = header_proof(&other_hs, &other_win, 4);
        assert!(anchor_from_header_proof(&beacon, ANCHOR, &p, &foreign).is_err());
        // Dynamically activated shards are not supported.
        let dynamic = test_params(7);
        assert!(anchor_from_header_proof(&beacon, ANCHOR, &dynamic, &ok).is_err());
        assert_eq!(dynamic.activation_height(), None);
    }

    #[test]
    fn at_the_activation_block_the_anchor_comes_from_the_beacon_tip() {
        let (hs, _) = build_proving(8);
        let mut beacon = ThinBeaconState::new(ANCHOR, [0xFF; 32], 1);
        for h in &hs[..5] {
            beacon.apply_header(h).unwrap();
        }
        let a = discover_anchor(&beacon, &test_params(0)).expect("tip is block 4");
        assert_eq!(a.root, beacon.root());
        beacon.apply_header(&hs[5]).unwrap();
        assert!(discover_anchor(&beacon, &test_params(0)).is_none(), "past it: needs the header proof");
    }
}
