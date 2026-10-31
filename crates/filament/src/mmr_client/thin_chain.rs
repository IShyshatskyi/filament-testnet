//! Thin beacon chain state for the light client (`docs/plan/Filament_Thin_Sync_Design.md`).
//!
//! Holds only the MMR peaks, the leaf count and the last [`RECENT_HEADERS`] full
//! headers. A new block is accepted one header at a time:
//!
//! 1. its height is the next one;
//! 2. its `prev_mmr_root` equals the root Filament computed itself;
//! 3. its proof-of-work meets the target its own `bits` claim;
//! 4. appending its leaf to the stored peaks yields the new root and the new
//!    chain weight, both computed here, never received.
//!
//! The weight is the rBits of the locally computed root, so it needs no field on
//! the wire. A peer can lie about nothing it is not also proving.
//!
//! Limits (stated, not hidden): step 3 checks the work a header claims, not that
//! the claim matches the DAA's expected difficulty, so a cheap fake chain still
//! has to be lighter than the real one and lose the comparison between Keystones.

use std::collections::VecDeque;

use common_types::common::blocks::beacon_wire_header::{WireBeaconHeader, WIRE_BEACON_HEADER_SIZE};
use common_types::common::proofs::{ThinSessionResponse, ThinTipResponse};
use common_types::common::crypto::weighted_hash::{bag_peaks_weighted_u128, WeightedHash};
use common_types::common::weighted_mmr_core::WeightedMMR;

/// How many full headers are kept (owner decision, Oct 29, 2026).
pub const RECENT_HEADERS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThinSyncError {
    /// The header is not the next height.
    WrongHeight { expected: u32, got: u32 },
    /// `prev_mmr_root` does not match the root computed from the stored peaks.
    PrevRootMismatch,
    /// Proof-of-work check failed.
    BadPow(&'static str),
    /// The leaf count would overflow.
    Overflow,
    /// A session or header response is malformed or inconsistent.
    BadResponse(String),
}

impl std::fmt::Display for ThinSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongHeight { expected, got } => write!(f, "expected height {expected}, got {got}"),
            Self::PrevRootMismatch => write!(f, "prev_mmr_root does not match the locally computed root"),
            Self::BadPow(why) => write!(f, "proof-of-work check failed: {why}"),
            Self::Overflow => write!(f, "leaf count overflow"),
            Self::BadResponse(why) => write!(f, "bad response: {why}"),
        }
    }
}

impl std::error::Error for ThinSyncError {}

fn decode_headers_hex(hex_str: &str) -> Result<Vec<WireBeaconHeader>, ThinSyncError> {
    let bytes = hex::decode(hex_str).map_err(|_| ThinSyncError::BadResponse("headers are not valid hex".into()))?;
    if bytes.len() % WIRE_BEACON_HEADER_SIZE != 0 {
        return Err(ThinSyncError::BadResponse("headers are not whole 150-byte records".into()));
    }
    bytes
        .chunks_exact(WIRE_BEACON_HEADER_SIZE)
        .map(|c| WireBeaconHeader::deserialize(c).map_err(ThinSyncError::BadResponse))
        .collect()
}

/// What to do after a tip poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    /// Same height and same root.
    UpToDate,
    /// The peer is behind us; wait, do not resync.
    PeerBehind,
    /// The peer is ahead: fetch the headers from this height.
    FetchHeaders { from: u32 },
    /// No state yet, or the peer has a different chain at our height: start a new session.
    NewSession,
}

/// What the sync loop needs from a thin chain state, beacon or shard.
pub trait ThinState: Clone + Send + Sync + 'static {
    fn leaf_count(&self) -> u32;
    fn root(&self) -> WeightedHash;
    /// Chain weight, computed locally from the proven peaks.
    fn weight(&self) -> u128;
    /// `prev_mmr_root` of the held full header at `height`, if it is one of the recent ones.
    fn prev_root_at(&self, height: u32) -> Option<WeightedHash>;
    fn height(&self) -> Option<u32> {
        self.leaf_count().checked_sub(1)
    }
}

impl ThinState for ThinBeaconState {
    fn leaf_count(&self) -> u32 {
        ThinBeaconState::leaf_count(self)
    }
    fn root(&self) -> WeightedHash {
        ThinBeaconState::root(self)
    }
    fn weight(&self) -> u128 {
        ThinBeaconState::weight(self)
    }
    fn prev_root_at(&self, height: u32) -> Option<WeightedHash> {
        self.recent().find(|h| h.height == height).map(|h| h.prev_mmr_root)
    }
}

/// Decide the next step from the local state and one peer's tip poll.
pub fn plan_sync<S: ThinState>(state: Option<&S>, tip: &ThinTipResponse) -> SyncAction {
    let Some(st) = state else { return SyncAction::NewSession };
    use std::cmp::Ordering::*;
    match tip.leaf_count.cmp(&st.leaf_count()) {
        Equal if tip.root_hex == hex::encode(<[u8; 32]>::from(st.root())) => SyncAction::UpToDate,
        Equal => SyncAction::NewSession,
        Greater => SyncAction::FetchHeaders { from: st.leaf_count() },
        Less => SyncAction::PeerBehind,
    }
}

#[derive(Debug, Clone)]
pub struct ThinBeaconState {
    anchor: WeightedHash,
    initial_target: [u8; 32],
    genesis_asserted_s_bits: u32,
    /// Peaks, left to right (the order `compute_peaks_after_append` uses).
    peaks: Vec<WeightedHash>,
    leaf_count: u32,
    root: WeightedHash,
    weight: u128,
    recent: VecDeque<WireBeaconHeader>,
}

impl ThinBeaconState {
    /// Empty state anchored at the network's bitcoin anchor hash. The first
    /// header applied must be the genesis header (height 0).
    pub fn new(bitcoin_anchor_hash: [u8; 32], initial_target: [u8; 32], genesis_asserted_s_bits: u32) -> Self {
        let anchor = WeightedHash::from_anchor(&bitcoin_anchor_hash);
        Self {
            anchor,
            initial_target,
            genesis_asserted_s_bits,
            peaks: Vec::new(),
            leaf_count: 0,
            root: anchor,
            weight: 0,
            recent: VecDeque::with_capacity(RECENT_HEADERS),
        }
    }

    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    /// Height of the tip, `None` before genesis.
    pub fn height(&self) -> Option<u32> {
        self.leaf_count.checked_sub(1)
    }

    pub fn root(&self) -> WeightedHash {
        self.root
    }

    /// Chain weight, computed locally from the peaks.
    pub fn weight(&self) -> u128 {
        self.weight
    }

    pub fn peaks(&self) -> &[WeightedHash] {
        &self.peaks
    }

    pub fn tip(&self) -> Option<&WireBeaconHeader> {
        self.recent.back()
    }

    /// The last (up to) [`RECENT_HEADERS`] headers, oldest first.
    pub fn recent(&self) -> impl Iterator<Item = &WireBeaconHeader> {
        self.recent.iter()
    }

    /// Build the state from a once-per-session summary. Everything is checked:
    /// the range proof's peaks bag to its root and the leaves chain back to the
    /// anchor; the response root and leaf count agree with the proof; every
    /// header is PoW-valid and its leaf equals the proof's leaf at that index
    /// (a header's PoW hash covers its `prev_mmr_root`, so the leaf binds it).
    /// The chain weight is computed from the proven peaks, not received.
    pub fn from_session(
        bitcoin_anchor_hash: [u8; 32],
        initial_target: [u8; 32],
        genesis_asserted_s_bits: u32,
        resp: &ThinSessionResponse,
    ) -> Result<Self, ThinSyncError> {
        let bad = |m: &str| ThinSyncError::BadResponse(m.to_string());
        let headers = decode_headers_hex(&resp.headers_hex)?;
        if headers.is_empty() {
            return Err(bad("no headers"));
        }
        let n = headers.len() as u32;
        let first = resp.leaf_count.checked_sub(n).ok_or_else(|| bad("more headers than leaves"))?;
        for (i, h) in headers.iter().enumerate() {
            if h.height != first + i as u32 {
                return Err(bad("headers are not consecutive up to the tip"));
            }
        }
        let mut st = Self::new(bitcoin_anchor_hash, initial_target, genesis_asserted_s_bits);

        let Some(proof) = &resp.range_proof else {
            // Only a genesis-only chain has no proof: replay its single header.
            if resp.leaf_count != 1 {
                return Err(bad("a proof is required once the chain has more than the genesis block"));
            }
            st.apply_header(&headers[0])?;
            return Ok(st);
        };
        if proof.leaf_count != resp.leaf_count || proof.end != resp.leaf_count {
            return Err(bad("proof does not end at the response's leaf count"));
        }
        if hex::encode(<[u8; 32]>::from(proof.root)) != resp.root_hex {
            return Err(bad("response root differs from the proof root"));
        }
        if !proof.verify_with_anchor(bitcoin_anchor_hash) {
            return Err(bad("range proof does not verify against the anchor"));
        }
        if first > proof.start {
            return Err(bad("headers do not cover the proof range"));
        }
        for h in headers.iter().filter(|h| h.height >= proof.start.max(1)) {
            st.check_pow(h)?;
            let idx = (h.height - proof.start) as usize;
            let leaf = WeightedHash::from_leaf_rbits(&h.pow_hash(), h.bits);
            if proof.leaves.get(idx) != Some(&leaf) {
                return Err(bad("a header does not match the proof's leaf"));
            }
        }
        st.weight = bag_peaks_weighted_u128(&proof.peaks, st.anchor).1;
        st.peaks = proof.peaks.clone();
        st.leaf_count = resp.leaf_count;
        st.root = proof.root;
        let keep = headers.len().saturating_sub(RECENT_HEADERS);
        st.recent = headers.into_iter().skip(keep).collect();
        Ok(st)
    }

    /// Apply consecutive headers from an incremental response, stopping at the
    /// first failure. Returns how many were applied.
    pub fn apply_headers_hex(&mut self, headers_hex: &str) -> Result<usize, (usize, ThinSyncError)> {
        let headers = decode_headers_hex(headers_hex).map_err(|e| (0, e))?;
        for (i, h) in headers.iter().enumerate() {
            self.apply_header(h).map_err(|e| (i, e))?;
        }
        Ok(headers.len())
    }

    /// Proof-of-work check of one header against this state's genesis facts.
    pub fn check_pow(&self, h: &WireBeaconHeader) -> Result<(), ThinSyncError> {
        // Same check as filament-p2p::pow_validator (kept local so thin_chain
        // does not require the optional full-node p2p feature).
        let _ = self.genesis_asserted_s_bits;
        let pow = h.pow_hash();
        for i in 0..32 {
            if pow[i] < self.initial_target[i] {
                return Ok(());
            }
            if pow[i] > self.initial_target[i] {
                return Err(ThinSyncError::BadPow("pow does not meet target"));
            }
        }
        Ok(())
    }

    /// Verify `h` as the next block and append it. On error the state is unchanged.
    pub fn apply_header(&mut self, h: &WireBeaconHeader) -> Result<(), ThinSyncError> {
        if h.height != self.leaf_count {
            return Err(ThinSyncError::WrongHeight { expected: self.leaf_count, got: h.height });
        }
        if h.height == 0 {
            // Genesis links to the bitcoin anchor; only its 28-byte hash part is
            // significant (the last 4 bytes of the raw anchor are not rBits).
            if h.prev_mmr_root.hash_bytes() != self.anchor.hash_bytes() {
                return Err(ThinSyncError::PrevRootMismatch);
            }
        } else if h.prev_mmr_root != self.root {
            return Err(ThinSyncError::PrevRootMismatch);
        }
        // Genesis is trusted from config (never PoW-checked), like every other node.
        self.check_pow(h)?;

        let next_count = self.leaf_count.checked_add(1).ok_or(ThinSyncError::Overflow)?;
        let leaf = WeightedHash::from_leaf_rbits(&h.pow_hash(), h.bits);
        let (peaks, root, weight) =
            WeightedMMR::compute_peaks_after_append(&self.peaks, self.leaf_count, leaf, self.anchor);

        self.peaks = peaks;
        self.root = root;
        self.weight = weight;
        self.leaf_count = next_count;
        if self.recent.len() == RECENT_HEADERS {
            self.recent.pop_front();
        }
        self.recent.push_back(h.clone());
        Ok(())
    }
}


