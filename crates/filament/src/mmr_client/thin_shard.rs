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

use network_common::common::blocks::beacon_wire_header::WireBeaconHeader;
use network_common::common::blocks::shard_block::{Block, FullShardHeader};
use network_common::common::crypto::weighted_hash::{bag_peaks_weighted_u128, WeightedHash};
use network_common::common::genesis::genesis_config::{BeaconGenesisConfig, ShardGenesisConfig};
use network_common::common::blocks::shard_block::TxInclusionProof;
use network_common::common::proofs::{decode_shard_blocks, FullShardBlockData, ThinHeaderProofResponse, ThinShardBlocksResponse, ThinShardSessionResponse};
use network_common::common::merged_mining_check::verify_shard_id_and_mmn;
use network_common::common::mmr_math;

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
        .chunks_exact(network_common::common::blocks::beacon_wire_header::WIRE_BEACON_HEADER_SIZE)
        .map(|c| WireBeaconHeader::deserialize(c).map_err(ThinSyncError::BadResponse))
        .collect::<Result<_, _>>()?;
    if hs.len() != 2 || bytes.len() != 2 * network_common::common::blocks::beacon_wire_header::WIRE_BEACON_HEADER_SIZE {
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
            mmr_math::compute_peaks_after_append(&self.peaks, self.leaf_count, leaf, self.bag_anchor);
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
    use network_common::common::proofs::{WeightedMMRBatchProof, WeightedMMRRangeProof};
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
    use network_common::common::proofs::WeightedMMRBatchProof;
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
    if !proof.value_is_committed() {
        return Err("the output is a shard coinbase reward, whose amount the proof does not commit".into());
    }
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
