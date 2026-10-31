//! Thin beacon sync loop (`docs/plan/Filament_Thin_Sync_Design.md` §3, §9).
//!
//! One round, run every sync tick for the beacon chain:
//!
//! 1. Ask every configured Keystone for `GET /chain/tip` (about 100 bytes).
//! 2. Per Keystone, [`plan_sync`] picks the cheapest safe step: nothing (same
//!    root), fetch the missing headers (`GET /chain/headers/{from}`), or start a
//!    new session (`GET /chain/session`, once, with a range proof). Every
//!    answer is verified by [`ThinBeaconState`]; a failed header falls back to
//!    a session, a failed session marks the Keystone as rejected.
//! 3. Each Keystone that answered now has a *verified* state of its own chain.
//!    A state is trusted only when at least `required` distinct Keystones
//!    **contain** it (same root at the same leaf count, or ahead of it with a
//!    held header whose `prev_mmr_root` is that root). Among supported states
//!    the heaviest wins. Keystones that are on different chains are reported as
//!    a disagreement.
//!
//! The full `GET /chain/summary` is never requested here.
//!
//! What this does not check (also stated in `thin_chain`): that the work a
//! header claims matches the DAA's expected difficulty. A cheap fake chain has
//! to be lighter than the real one and lose the comparison between Keystones.

use std::time::{Duration, Instant};

use std::future::Future;
use std::pin::Pin;

use common_types::common::proofs::{
    ThinHeadersResponse, ThinSessionResponse, ThinShardBlocksResponse, ThinShardSessionResponse, ThinTipResponse,
};
use futures_util::FutureExt;
use serde::de::DeserializeOwned;

use crate::mmr_client::thin_chain::{plan_sync, SyncAction, ThinBeaconState, ThinState, RECENT_HEADERS};
use crate::mmr_client::thin_shard::{ShardAnchor, ThinShardParams, ThinShardState, RECENT_BLOCKS};

/// A gap bigger than this is cheaper to close with a new session than with headers.
pub const MAX_CATCH_UP_BLOCKS: u32 = 256;
/// A state counts as "synced" for this long after the last quorum round.
pub const QUORUM_FRESH_FOR: Duration = Duration::from_secs(90);
/// Per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Trusted genesis facts the PoW and anchor checks need.
#[derive(Debug, Clone)]
pub struct ThinSyncParams {
    pub bitcoin_anchor_hash: [u8; 32],
    pub initial_target: [u8; 32],
    pub genesis_asserted_s_bits: u32,
}

/// The state Filament holds, plus when it last had quorum.
#[derive(Debug, Clone)]
pub struct ThinSlot<S> {
    state: Option<S>,
    last_quorum_at: Option<Instant>,
}

impl<S> Default for ThinSlot<S> {
    fn default() -> Self {
        Self { state: None, last_quorum_at: None }
    }
}

pub type ThinBeaconSlot = ThinSlot<ThinBeaconState>;
pub type ThinShardSlot = ThinSlot<ThinShardState>;

/// Everything Filament holds for one thin-synced shard.
#[derive(Debug, Clone, Default)]
pub struct ShardThin {
    pub slot: ThinShardSlot,
    /// Derived from verified beacon data; `None` until the beacon is far enough along.
    pub anchor: Option<ShardAnchor>,
    /// Why the shard cannot be followed (`unsupported_dynamic_shard`), or that it waits (`awaiting_anchor`).
    pub note: Option<&'static str>,
}

impl ShardThin {
    /// Status for the API: the slot's quorum status, or the reason the shard is not followed.
    pub fn status(&self, now: Instant) -> &'static str {
        match self.note {
            Some("unsupported_dynamic_shard") => "unsupported",
            _ => self.slot.status(now),
        }
    }
}

impl<S: ThinState> ThinSlot<S> {
    pub fn state(&self) -> Option<&S> {
        self.state.as_ref()
    }

    pub fn install(&mut self, st: S, now: Instant) {
        self.state = Some(st);
        self.last_quorum_at = Some(now);
    }

    pub fn mark_quorum(&mut self, now: Instant) {
        self.last_quorum_at = Some(now);
    }

    /// `bootstrapping` before the first quorum, `synced` while quorum is fresh,
    /// `insufficient_peers` once it has gone stale.
    pub fn status(&self, now: Instant) -> &'static str {
        match (&self.state, self.last_quorum_at) {
            (None, _) => "bootstrapping",
            (Some(_), Some(t)) if now.duration_since(t) <= QUORUM_FRESH_FOR => "synced",
            (Some(_), _) => "insufficient_peers",
        }
    }

    pub fn tip_height(&self) -> u32 {
        self.state.as_ref().and_then(|s| s.height()).unwrap_or(0)
    }
}

/// What one round did, for logs, tests and the disagreement event.
#[derive(Debug, Default, Clone)]
pub struct RoundReport {
    /// A different state was installed this round.
    pub installed: bool,
    /// Some state reached the required number of Keystones.
    pub quorum: bool,
    /// `(url, chain_weight, tip_height)` of every verified Keystone, when two of them are on different chains.
    pub disagreement: Option<Vec<(String, u128, u32)>>,
    /// Keystones whose answers failed verification.
    pub rejected: Vec<String>,
    /// Keystones that did not answer.
    pub unreachable: Vec<String>,
}

enum PeerOutcome<S> {
    State(S),
    /// Its chain is shorter than ours: it vouches for nothing newer.
    Behind,
    Rejected(String),
    Unreachable(String),
}

pub(crate) async fn get_json<T: DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T, String> {
    let resp = http.get(url).timeout(REQUEST_TIMEOUT).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json::<T>().await.map_err(|e| format!("bad response body: {e}"))
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What differs between the beacon and one shard: the routes, and how an answer is verified.
pub trait ThinKind: Sync {
    type State: ThinState;
    /// Path (after the Keystone base URL) of the tip poll.
    fn tip_path(&self) -> String;
    /// Start a session from the Keystone's session response (verified).
    fn new_session<'a>(&'a self, http: &'a reqwest::Client, base: &'a str) -> Fut<'a, Result<Self::State, String>>;
    /// Fetch and apply one batch of consecutive blocks starting at `st.leaf_count()`.
    fn catch_up_step<'a>(
        &'a self,
        http: &'a reqwest::Client,
        base: &'a str,
        st: Self::State,
    ) -> Fut<'a, Result<Self::State, String>>;
}

/// The beacon chain.
pub struct BeaconKind<'p>(pub &'p ThinSyncParams);

impl ThinKind for BeaconKind<'_> {
    type State = ThinBeaconState;

    fn tip_path(&self) -> String {
        "/chain/tip".into()
    }

    fn new_session<'a>(&'a self, http: &'a reqwest::Client, base: &'a str) -> Fut<'a, Result<ThinBeaconState, String>> {
        async move {
            let p = self.0;
            let resp: ThinSessionResponse =
                get_json(http, &format!("{base}/chain/session?headers={RECENT_HEADERS}")).await?;
            ThinBeaconState::from_session(p.bitcoin_anchor_hash, p.initial_target, p.genesis_asserted_s_bits, &resp)
                .map_err(|e| e.to_string())
        }
        .boxed()
    }

    fn catch_up_step<'a>(
        &'a self,
        http: &'a reqwest::Client,
        base: &'a str,
        mut st: ThinBeaconState,
    ) -> Fut<'a, Result<ThinBeaconState, String>> {
        async move {
            let from = st.leaf_count();
            let resp: ThinHeadersResponse = get_json(http, &format!("{base}/chain/headers/{from}?max=64")).await?;
            if resp.from != from || resp.headers_hex.is_empty() {
                return Err("headers response does not start where asked".into());
            }
            st.apply_headers_hex(&resp.headers_hex).map_err(|(_, e)| e.to_string())?;
            Ok(st)
        }
        .boxed()
    }
}

/// One shard, anchored at `anchor`.
pub struct ShardKind<'p> {
    pub params: &'p ThinShardParams,
    pub anchor: ShardAnchor,
}

impl ThinKind for ShardKind<'_> {
    type State = ThinShardState;

    fn tip_path(&self) -> String {
        format!("/shard/{}/chain/tip", self.params.shard_id)
    }

    fn new_session<'a>(&'a self, http: &'a reqwest::Client, base: &'a str) -> Fut<'a, Result<ThinShardState, String>> {
        async move {
            let id = self.params.shard_id;
            let resp: ThinShardSessionResponse =
                get_json(http, &format!("{base}/shard/{id}/chain/session?headers={RECENT_BLOCKS}")).await?;
            ThinShardState::from_session(self.params.clone(), self.anchor, &resp).map_err(|e| e.to_string())
        }
        .boxed()
    }

    fn catch_up_step<'a>(
        &'a self,
        http: &'a reqwest::Client,
        base: &'a str,
        mut st: ThinShardState,
    ) -> Fut<'a, Result<ThinShardState, String>> {
        async move {
            let id = self.params.shard_id;
            let from = st.leaf_count();
            let resp: ThinShardBlocksResponse =
                get_json(http, &format!("{base}/shard/{id}/chain/headers/{from}")).await?;
            if resp.from != from || resp.blocks_hex.is_empty() {
                return Err("blocks response does not start where asked".into());
            }
            st.apply_blocks_hex(&resp.blocks_hex).map_err(|(_, e)| e.to_string())?;
            Ok(st)
        }
        .boxed()
    }
}

/// Extend `st` with blocks from `base` until it reaches `target_leaves`.
async fn catch_up<K: ThinKind>(
    kind: &K,
    http: &reqwest::Client,
    base: &str,
    mut st: K::State,
    target_leaves: u32,
) -> Result<K::State, String> {
    while st.leaf_count() < target_leaves {
        let before = st.leaf_count();
        st = kind.catch_up_step(http, base, st).await?;
        if st.leaf_count() <= before {
            return Err("catch-up made no progress".into());
        }
    }
    Ok(st)
}

async fn peer_outcome<K: ThinKind>(
    kind: &K,
    http: &reqwest::Client,
    base: &str,
    current: Option<&K::State>,
) -> PeerOutcome<K::State> {
    let tip: ThinTipResponse = match get_json(http, &format!("{base}{}", kind.tip_path())).await {
        Ok(t) => t,
        Err(e) => return PeerOutcome::Unreachable(e),
    };
    let session = || async {
        match kind.new_session(http, base).await {
            Ok(s) => PeerOutcome::State(s),
            Err(e) => PeerOutcome::Rejected(e),
        }
    };
    match plan_sync(current, &tip) {
        SyncAction::UpToDate => PeerOutcome::State(current.expect("UpToDate implies a state").clone()),
        SyncAction::PeerBehind => PeerOutcome::Behind,
        SyncAction::NewSession => session().await,
        SyncAction::FetchHeaders { from } => {
            let cur = current.expect("FetchHeaders implies a state");
            if tip.leaf_count.saturating_sub(from) > MAX_CATCH_UP_BLOCKS {
                return session().await;
            }
            match catch_up(kind, http, base, cur.clone(), tip.leaf_count).await {
                Ok(s) => PeerOutcome::State(s),
                // Bad header, wrong link or a reorg below our tip: start over from a session.
                Err(_) => session().await,
            }
        }
    }
}

/// GET `url` and decode the JSON body (10 s timeout).
pub(crate) async fn fetch_json<T: DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T, String> {
    get_json(http, url).await
}

/// Does `peer`'s chain contain `cand`'s tip? Same leaf count and root, or the
/// peer is ahead and holds the header that follows `cand` with `cand`'s root as
/// its `prev_mmr_root`.
pub fn contains<S: ThinState>(peer: &S, cand: &S) -> bool {
    use std::cmp::Ordering::*;
    match peer.leaf_count().cmp(&cand.leaf_count()) {
        Equal => peer.root() == cand.root(),
        Greater => peer.prev_root_at(cand.leaf_count()) == Some(cand.root()),
        Less => false,
    }
}

fn same_state<S: ThinState>(a: &S, b: &S) -> bool {
    a.leaf_count() == b.leaf_count() && a.root() == b.root()
}

/// Pure decision step: given the verified state of each answering Keystone,
/// pick the state to hold. Candidates are the current state and every
/// Keystone's state; one needs `required` Keystones that contain it, and the
/// heaviest supported one wins (ties: the longer chain).
pub fn choose<'a, S: ThinState>(
    current: Option<&'a S>,
    views: &'a [(String, S)],
    required: usize,
) -> Option<&'a S> {
    let required = required.max(1);
    current
        .into_iter()
        .chain(views.iter().map(|(_, s)| s))
        .filter(|c| views.iter().filter(|(_, p)| contains(p, c)).count() >= required)
        .max_by_key(|c| (c.weight(), c.leaf_count()))
}

/// `Some` when two Keystones are on chains where neither contains the other.
pub fn disagreement<S: ThinState>(views: &[(String, S)]) -> Option<Vec<(String, u128, u32)>> {
    let split = views.iter().enumerate().any(|(i, (_, a))| {
        views.iter().skip(i + 1).any(|(_, b)| !contains(a, b) && !contains(b, a))
    });
    split.then(|| {
        views
            .iter()
            .map(|(u, s)| (u.clone(), s.weight(), s.height().unwrap_or(0)))
            .collect()
    })
}

/// Run one round of the beacon against `urls` (each a Keystone REST base URL).
pub async fn thin_round(
    http: &reqwest::Client,
    urls: &[String],
    p: &ThinSyncParams,
    required: usize,
    slot: &mut ThinBeaconSlot,
) -> RoundReport {
    run_round(&BeaconKind(p), http, urls, required, slot).await
}

/// Run one round of one shard against `urls`.
pub async fn thin_shard_round(
    http: &reqwest::Client,
    urls: &[String],
    params: &ThinShardParams,
    anchor: ShardAnchor,
    required: usize,
    slot: &mut ThinShardSlot,
) -> RoundReport {
    run_round(&ShardKind { params, anchor }, http, urls, required, slot).await
}

/// One round for any chain kind: poll every Keystone, verify each answer, pick the state at least
/// `required` Keystones contain.
pub async fn run_round<K: ThinKind>(
    kind: &K,
    http: &reqwest::Client,
    urls: &[String],
    required: usize,
    slot: &mut ThinSlot<K::State>,
) -> RoundReport {
    let current = slot.state().cloned();
    let outcomes = futures_util::future::join_all(
        urls.iter().map(|u| peer_outcome(kind, http, u, current.as_ref())),
    )
    .await;

    let mut report = RoundReport::default();
    let mut views: Vec<(String, K::State)> = Vec::new();
    for (url, out) in urls.iter().zip(outcomes) {
        match out {
            PeerOutcome::State(s) => views.push((url.clone(), s)),
            PeerOutcome::Behind => {}
            PeerOutcome::Rejected(why) => {
                log::warn!("thin sync: {url} rejected: {why}");
                report.rejected.push(url.clone());
            }
            PeerOutcome::Unreachable(why) => {
                log::warn!("thin sync: {url} unreachable: {why}");
                report.unreachable.push(url.clone());
            }
        }
    }
    report.disagreement = disagreement(&views);

    let now = Instant::now();
    if let Some(best) = choose(current.as_ref(), &views, required) {
        report.quorum = true;
        if current.as_ref().map_or(true, |c| !same_state(c, best)) {
            slot.install(best.clone(), now);
            report.installed = true;
        } else {
            slot.mark_quorum(now);
        }
    }
    report
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mmr_client::thin_chain::tests::{build_proving_bits, build_proving_salted, session, ANCHOR};
    use axum::{
        extract::{Path, Query, State},
        http::StatusCode,
        routing::get,
        Json, Router,
    };
    use common_types::common::blocks::beacon_wire_header::WireBeaconHeader;
    use common_types::common::windowed_weighted_mmr::WindowedWeightedMMR;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// What one mock Keystone serves: its chain, and counters per route.
    struct Chain {
        headers: Vec<WireBeaconHeader>,
        win: WindowedWeightedMMR,
        salt: u32,
        bits: u32,
    }

    pub(crate) struct Mock {
        chain: Mutex<Chain>,
        pub(crate) tip_calls: AtomicUsize,
        pub(crate) session_calls: AtomicUsize,
        pub(crate) headers_calls: AtomicUsize,
        pub(crate) summary_calls: AtomicUsize,
        pub(crate) header_proof_calls: AtomicUsize,
        /// Serve a wrong root in every response (a lying Keystone).
        lie_root: bool,
        /// Corrupt the first byte of the prev root inside served headers.
        lie_headers: std::sync::atomic::AtomicBool,
        /// Serve a wrong leaf count in sessions.
        lie_count: bool,
    }

    impl Mock {
        fn build(n: u32, salt: u32, lie_root: bool, lie_headers: bool, lie_count: bool) -> Arc<Self> {
            Self::build_bits(n, salt, common_types::common::crypto::weighted_hash::u128_to_rbits(1), lie_root, lie_headers, lie_count)
        }
        fn build_bits(n: u32, salt: u32, bits: u32, lie_root: bool, lie_headers: bool, lie_count: bool) -> Arc<Self> {
            let (hs, win) = build_proving_bits(n, salt, bits);
            Arc::new(Self {
                chain: Mutex::new(Chain { headers: hs, win, salt, bits }),
                tip_calls: AtomicUsize::new(0),
                session_calls: AtomicUsize::new(0),
                headers_calls: AtomicUsize::new(0),
                summary_calls: AtomicUsize::new(0),
                header_proof_calls: AtomicUsize::new(0),
                lie_root,
                lie_headers: std::sync::atomic::AtomicBool::new(lie_headers),
                lie_count,
            })
        }
        pub(crate) fn new(n: u32) -> Arc<Self> {
            Self::build(n, 0, false, false, false)
        }
        /// A honest Keystone whose headers all carry the work field `bits`.
        pub(crate) fn with_bits(n: u32, bits: u32) -> Arc<Self> {
            Self::build_bits(n, 0, bits, false, false, false)
        }
        fn liar(n: u32, root: bool, headers: bool, count: bool) -> Arc<Self> {
            Self::build(n, 0, root, headers, count)
        }
        /// Replace the chain with another valid one (a fork from genesis).
        pub(crate) fn fork_to(&self, n: u32, salt: u32) {
            let bits = self.chain.lock().unwrap().bits;
            let (hs, win) = build_proving_bits(n, salt, bits);
            *self.chain.lock().unwrap() = Chain { headers: hs, win, salt, bits };
        }
    }

    async fn tip(State(m): State<Arc<Mock>>) -> Json<ThinTipResponse> {
        m.tip_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap();
        let n = c.headers.len() as u32;
        let root = if m.lie_root { [0x42; 32] } else { c.win.get_root_bytes() };
        Json(ThinTipResponse { height: n.checked_sub(1), leaf_count: n, root_hex: hex::encode(root) })
    }

    async fn sess(State(m): State<Arc<Mock>>) -> Json<ThinSessionResponse> {
        m.session_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap();
        let mut r = session(&c.headers, &c.win, c.headers.len().min(16));
        if m.lie_root {
            r.root_hex = hex::encode([0x42; 32]);
        }
        if m.lie_count {
            r.leaf_count += 1;
        }
        if m.lie_headers.load(Ordering::SeqCst) {
            let mut b = hex::decode(&r.headers_hex).unwrap();
            b[20] ^= 0xFF;
            r.headers_hex = hex::encode(b);
        }
        Json(r)
    }

    async fn hdrs(
        State(m): State<Arc<Mock>>,
        Path(from): Path<u32>,
        Query(q): Query<HashMap<String, u32>>,
    ) -> Result<Json<ThinHeadersResponse>, StatusCode> {
        m.headers_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap();
        let max = q.get("max").copied().unwrap_or(64).min(64) as usize;
        let mut bytes: Vec<u8> = c.headers.iter().skip(from as usize).take(max).flat_map(|h| h.serialize()).collect();
        if m.lie_headers.load(Ordering::SeqCst) && bytes.len() > 20 {
            bytes[20] ^= 0xFF;
        }
        Ok(Json(ThinHeadersResponse { from, leaf_count: c.headers.len() as u32, headers_hex: hex::encode(bytes) }))
    }

    async fn summary(State(m): State<Arc<Mock>>) -> StatusCode {
        m.summary_calls.fetch_add(1, Ordering::SeqCst);
        StatusCode::NOT_FOUND
    }

    /// `GET /chain/header-proof/{from}?count=2&at=LEAVES` for the shard anchor.
    async fn hproof(
        State(m): State<Arc<Mock>>,
        Path(from): Path<u32>,
        Query(q): Query<HashMap<String, u32>>,
    ) -> Result<Json<common_types::common::proofs::ThinHeaderProofResponse>, StatusCode> {
        m.header_proof_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap();
        let n = c.headers.len() as u32;
        if q.get("at").copied().unwrap_or(n) != n || from == 0 || from + 2 > n {
            return Err(StatusCode::BAD_REQUEST);
        }
        let hs = &c.headers[from as usize..from as usize + 2];
        Ok(Json(common_types::common::proofs::ThinHeaderProofResponse {
            from,
            leaf_count: n,
            root_hex: hex::encode(c.win.get_root_bytes()),
            headers_hex: hex::encode(hs.iter().flat_map(|h| h.serialize()).collect::<Vec<u8>>()),
            range_proof: c.win.prove_range(from, n).map_err(|_| StatusCode::BAD_REQUEST)?,
        }))
    }

    /// The mock's routes, for tests that merge several mocks into one server.
    pub(crate) fn router(m: Arc<Mock>) -> Router {
        Router::new()
            .route("/chain/tip", get(tip))
            .route("/chain/session", get(sess))
            .route("/chain/headers/{from}", get(hdrs))
            .route("/chain/header-proof/{from}", get(hproof))
            .route("/chain/summary", get(summary))
            .with_state(m)
    }

    pub(crate) async fn serve(m: Arc<Mock>) -> String {
        let app = router(m);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn params() -> ThinSyncParams {
        ThinSyncParams { bitcoin_anchor_hash: ANCHOR, initial_target: [0xFF; 32], genesis_asserted_s_bits: 1 }
    }

    /// Grow a mock's chain by `k` valid blocks (same chain, longer).
    pub(crate) fn extend(m: &Mock, k: u32) {
        let (n, salt) = {
            let c = m.chain.lock().unwrap();
            (c.headers.len() as u32 + k, c.salt)
        };
        m.fork_to(n, salt);
    }

    async fn round(urls: &[String], required: usize, slot: &mut ThinBeaconSlot) -> RoundReport {
        thin_round(&reqwest::Client::new(), urls, &params(), required, slot).await
    }

    #[tokio::test]
    async fn first_sync_uses_one_session_per_keystone_and_no_summary() {
        let (a, b) = (Mock::new(40), Mock::new(40));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.quorum && r.installed, "{r:?}");
        let st = slot.state().unwrap();
        assert_eq!((st.leaf_count(), st.height()), (40, Some(39)));
        assert_eq!(slot.status(Instant::now()), "synced");
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 1);
        assert_eq!(a.headers_calls.load(Ordering::SeqCst), 0);
        assert_eq!(a.summary_calls.load(Ordering::SeqCst) + b.summary_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn following_twenty_new_blocks_uses_headers_only() {
        let (a, b) = (Mock::new(40), Mock::new(40));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        round(&urls, 2, &mut slot).await;
        extend(&a, 20);
        extend(&b, 20);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed && r.quorum, "{r:?}");
        assert_eq!(slot.state().unwrap().leaf_count(), 60);
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 1, "no second session");
        assert_eq!(a.headers_calls.load(Ordering::SeqCst), 1);
        // Up to date: tips only.
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.quorum && !r.installed);
        assert_eq!(a.headers_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_keystone_does_not_sync_when_two_are_required() {
        let a = Mock::new(40);
        let urls = vec![serve(a).await];
        let mut slot = ThinBeaconSlot::default();
        let r = round(&urls, 2, &mut slot).await;
        assert!(!r.quorum && !r.installed);
        assert!(slot.state().is_none());
        assert_eq!(slot.status(Instant::now()), "bootstrapping");
        // The insecure override accepts it.
        let r = round(&urls, 1, &mut slot).await;
        assert!(r.quorum && r.installed);
    }

    #[tokio::test]
    async fn a_lying_keystone_is_ignored_and_an_honest_pair_is_used() {
        let (a, b) = (Mock::new(40), Mock::new(40));
        for (name, liar) in [
            ("bad root", Mock::liar(40, true, false, false)),
            ("bad header", Mock::liar(40, false, true, false)),
            ("wrong leaf count", Mock::liar(40, false, false, true)),
        ] {
            let urls = vec![serve(a.clone()).await, serve(b.clone()).await, serve(liar.clone()).await];
            let mut slot = ThinBeaconSlot::default();
            let r = round(&urls, 2, &mut slot).await;
            assert!(r.quorum && r.installed, "{name}: {r:?}");
            assert_eq!(slot.state().unwrap().leaf_count(), 40, "{name}");
            assert!(!r.rejected.is_empty(), "{name}: the liar is reported as rejected: {r:?}");

            // A liar plus one honest Keystone is not enough for quorum 2.
            let urls = vec![serve(a.clone()).await, serve(liar).await];
            let mut slot = ThinBeaconSlot::default();
            let r = round(&urls, 2, &mut slot).await;
            assert!(!r.quorum && slot.state().is_none(), "{name}: {r:?}");
        }
    }

    #[tokio::test]
    async fn a_lying_header_feed_after_sync_is_rejected_and_the_honest_one_followed() {
        let (honest, good, liar) = (Mock::new(40), Mock::new(40), Mock::new(40));
        let boot = vec![serve(honest.clone()).await, serve(good.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        assert!(round(&boot, 2, &mut slot).await.installed);
        // The liar was honest so far; from now on it serves corrupted headers.
        liar.lie_headers.store(true, Ordering::SeqCst);
        extend(&honest, 5);
        extend(&liar, 5);
        let urls = vec![serve(honest.clone()).await, serve(liar.clone()).await];
        let r = round(&urls, 1, &mut slot).await;
        assert!(r.quorum && r.installed, "{r:?}");
        assert_eq!(slot.state().unwrap().leaf_count(), 45);
        assert!(r.rejected.contains(&urls[1]), "{r:?}");
        assert!(liar.headers_calls.load(Ordering::SeqCst) >= 1, "it was asked for headers first");
    }

    #[tokio::test]
    async fn a_reorg_at_the_same_height_starts_a_new_session() {
        let (a, b) = (Mock::new(40), Mock::new(40));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        round(&urls, 2, &mut slot).await;
        let before = slot.state().unwrap().root();
        // Both Keystones now serve another chain of the same length.
        a.fork_to(40, 1);
        b.fork_to(40, 1);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed && r.quorum, "{r:?}");
        assert_ne!(slot.state().unwrap().root(), before);
        assert_eq!(slot.state().unwrap().leaf_count(), 40);
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 2, "a new session, not headers");
    }

    #[tokio::test]
    async fn keystones_on_different_chains_are_reported_and_the_heavier_supported_one_needs_quorum() {
        let (a, b) = (Mock::new(40), Mock::build(40, 1, false, false, false));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        // Two required, but they disagree: no state, disagreement reported.
        let r = round(&urls, 2, &mut slot).await;
        assert!(!r.quorum && slot.state().is_none(), "{r:?}");
        assert_eq!(r.disagreement.as_ref().map(|d| d.len()), Some(2));
        // One required (dev mode): the heavier one wins.
        let r = round(&urls, 1, &mut slot).await;
        assert!(r.quorum && r.disagreement.is_some());
    }

    #[tokio::test]
    async fn a_gap_larger_than_the_limit_uses_a_session() {
        let (a, b) = (Mock::new(10), Mock::new(10));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinBeaconSlot::default();
        round(&urls, 2, &mut slot).await;
        let jump = MAX_CATCH_UP_BLOCKS + 10;
        extend(&a, jump);
        extend(&b, jump);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed, "{r:?}");
        assert_eq!(slot.state().unwrap().leaf_count(), 10 + jump);
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 2, "second session for the gap");
        assert_eq!(a.headers_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn contains_follows_the_held_headers() {
        let (hs, win) = build_proving_salted(30, 0);
        let long = ThinBeaconState::from_session(ANCHOR, [0xFF; 32], 1, &session(&hs, &win, 16)).unwrap();
        let (hs2, win2) = build_proving_salted(28, 0);
        let short = ThinBeaconState::from_session(ANCHOR, [0xFF; 32], 1, &session(&hs2, &win2, 16)).unwrap();
        assert!(contains(&long, &short), "the longer chain holds the header after the shorter tip");
        assert!(!contains(&short, &long));
        assert!(contains(&long, &long));
    }
}

#[cfg(test)]
pub(crate) mod shard_tests {
    use super::*;
    use crate::mmr_client::thin_shard::tests::{test_anchor, test_params, Chain};
    use axum::{
        extract::{Path, Query, State},
        routing::get,
        Json, Router,
    };
    use common_types::common::crypto::weighted_hash::WeightedHash;
    use common_types::common::proofs::{encode_shard_blocks, MAX_SHARD_BLOCKS_PER_REQUEST};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A mock Keystone's shard routes, serving a real mined chain.
    pub(crate) struct ShardMock {
        chain: Mutex<Arc<Chain>>,
        pub(crate) tip_calls: AtomicUsize,
        pub(crate) session_calls: AtomicUsize,
        pub(crate) blocks_calls: AtomicUsize,
        /// Break the proof-of-work of the first block of every answer.
        corrupt: AtomicBool,
        pub(crate) range_calls: AtomicUsize,
        /// The older `GET /shard/{id}/tip` the interim confirmation rule used (always claims 1000).
        pub(crate) old_tip_calls: AtomicUsize,
        /// Serve range proofs from this other chain instead (a lying Keystone).
        pub(crate) range_from: Mutex<Option<Arc<Chain>>>,
        pub(crate) tx_proof_calls: AtomicUsize,
        /// Forge the proved output's recipient (a lying Keystone).
        pub(crate) forge_recipient: Mutex<Option<[u8; 32]>>,
    }

    impl ShardMock {
        pub(crate) fn new(chain: Arc<Chain>) -> Arc<Self> {
            Arc::new(Self {
                chain: Mutex::new(chain),
                tip_calls: AtomicUsize::new(0),
                session_calls: AtomicUsize::new(0),
                blocks_calls: AtomicUsize::new(0),
                corrupt: AtomicBool::new(false),
                range_calls: AtomicUsize::new(0),
                old_tip_calls: AtomicUsize::new(0),
                range_from: Mutex::new(None),
                tx_proof_calls: AtomicUsize::new(0),
                forge_recipient: Mutex::new(None),
            })
        }
        pub(crate) fn serve_chain(&self, chain: Arc<Chain>) {
            *self.chain.lock().unwrap() = chain;
        }
    }

    async fn tip(State(m): State<Arc<ShardMock>>) -> Json<ThinTipResponse> {
        m.tip_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap().clone();
        let n = c.blocks.len() as u32;
        Json(ThinTipResponse { height: n.checked_sub(1), leaf_count: n, root_hex: hex::encode(c.win.get_root_bytes()) })
    }

    fn break_first(blocks_hex: &str) -> String {
        let mut blocks = common_types::common::proofs::decode_shard_blocks(blocks_hex).unwrap();
        blocks[0].beacon_header.nonce ^= 0xFFFF_FFFF;
        encode_shard_blocks(&blocks).unwrap()
    }

    async fn sess(State(m): State<Arc<ShardMock>>) -> Json<ThinShardSessionResponse> {
        m.session_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap().clone();
        let mut r = c.session(16);
        if m.corrupt.load(Ordering::SeqCst) {
            r.blocks_hex = break_first(&r.blocks_hex);
        }
        Json(r)
    }

    async fn blocks(
        State(m): State<Arc<ShardMock>>,
        Path((_id, from)): Path<(u16, u32)>,
        Query(_q): Query<HashMap<String, u32>>,
    ) -> Json<ThinShardBlocksResponse> {
        m.blocks_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap().clone();
        let slice: Vec<_> = c.blocks.iter().skip(from as usize).take(MAX_SHARD_BLOCKS_PER_REQUEST).cloned().collect();
        let mut hex_ = encode_shard_blocks(&slice).unwrap();
        if m.corrupt.load(Ordering::SeqCst) && !hex_.is_empty() {
            hex_ = break_first(&hex_);
        }
        Json(ThinShardBlocksResponse { from, leaf_count: c.blocks.len() as u32, blocks_hex: hex_ })
    }

    /// `GET /shard/{id}/chain/range/{start}/{end}` (inclusive end), as Keystone serves it.
    async fn range(
        State(m): State<Arc<ShardMock>>,
        Path((_id, start, end)): Path<(u16, u32, u32)>,
    ) -> Result<Json<common_types::common::proofs::WeightedMMRRangeProof>, axum::http::StatusCode> {
        m.range_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.range_from.lock().unwrap().clone().unwrap_or_else(|| m.chain.lock().unwrap().clone());
        c.win.prove_range(start, end + 1).map(Json).map_err(|_| axum::http::StatusCode::BAD_REQUEST)
    }

    /// `GET /shard/{id}/tx-proof?height=&output_idx=`, as Keystone serves it.
    async fn tx_proof(
        State(m): State<Arc<ShardMock>>,
        Path(_id): Path<u16>,
        Query(q): Query<HashMap<String, u32>>,
    ) -> Result<Json<common_types::common::blocks::shard_block::TxInclusionProof>, axum::http::StatusCode> {
        m.tx_proof_calls.fetch_add(1, Ordering::SeqCst);
        let c = m.chain.lock().unwrap().clone();
        let (h, o) = (*q.get("height").ok_or(axum::http::StatusCode::BAD_REQUEST)?, *q.get("output_idx").ok_or(axum::http::StatusCode::BAD_REQUEST)?);
        let mut p = c.body_at(h).tx_inclusion_proof(h, o).ok_or(axum::http::StatusCode::NOT_FOUND)?;
        if let Some(r) = *m.forge_recipient.lock().unwrap() {
            p.outputs[0].recipient = r;
        }
        Ok(Json(p))
    }

    async fn old_tip(State(m): State<Arc<ShardMock>>) -> Json<serde_json::Value> {
        m.old_tip_calls.fetch_add(1, Ordering::SeqCst);
        Json(serde_json::json!({ "height": 1000 }))
    }

    pub(crate) fn router(m: Arc<ShardMock>) -> Router {
        Router::new()
            .route("/shard/{id}/tip", get(old_tip))
            .route("/shard/{id}/chain/range/{start}/{end}", get(range))
            .route("/shard/{id}/chain/tip", get(tip))
            .route("/shard/{id}/chain/session", get(sess))
            .route("/shard/{id}/chain/headers/{from}", get(blocks))
            .route("/shard/{id}/tx-proof", get(tx_proof))
            .with_state(m)
    }

    async fn serve(m: Arc<ShardMock>) -> String {
        let app = router(m);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn round(urls: &[String], required: usize, slot: &mut ThinShardSlot) -> RoundReport {
        thin_shard_round(&reqwest::Client::new(), urls, &test_params(0), test_anchor(), required, slot).await
    }

    fn grown(from: &Chain, k: u32) -> Chain {
        // Same chain, longer: re-mine is deterministic per (height, prev, salt) up to the nonce search.
        let mut c = Chain::with_anchor_len(0, from.salt, from.anchor, from.blocks.len() as u32);
        c.extend(k);
        c
    }

    #[tokio::test]
    async fn first_sync_is_one_session_per_keystone() {
        let chain = Arc::new(Chain::with_len(0, 0, 40));
        let (a, b) = (ShardMock::new(chain.clone()), ShardMock::new(chain));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinShardSlot::default();
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.quorum && r.installed, "{r:?}");
        let st = slot.state().unwrap();
        assert_eq!((st.leaf_count(), st.height()), (40, Some(39)));
        assert_eq!(slot.status(Instant::now()), "synced");
        assert_eq!((a.session_calls.load(Ordering::SeqCst), a.blocks_calls.load(Ordering::SeqCst)), (1, 0));
    }

    #[tokio::test]
    async fn following_new_blocks_uses_the_blocks_route_only() {
        let chain = Arc::new(Chain::with_len(0, 0, 30));
        let (a, b) = (ShardMock::new(chain.clone()), ShardMock::new(chain.clone()));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinShardSlot::default();
        round(&urls, 2, &mut slot).await;
        let longer = Arc::new(grown(&chain, 12));
        a.serve_chain(longer.clone());
        b.serve_chain(longer.clone());
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed && r.quorum, "{r:?}");
        let st = slot.state().unwrap();
        assert_eq!((st.leaf_count(), st.root()), (42, longer.core.get_root()));
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 1, "no second session");
        assert_eq!(a.blocks_calls.load(Ordering::SeqCst), 1);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.quorum && !r.installed);
        assert_eq!(a.blocks_calls.load(Ordering::SeqCst), 1, "up to date: tips only");
    }

    #[tokio::test]
    async fn one_keystone_does_not_sync_when_two_are_required() {
        let a = ShardMock::new(Arc::new(Chain::with_len(0, 0, 20)));
        let urls = vec![serve(a).await];
        let mut slot = ThinShardSlot::default();
        let r = round(&urls, 2, &mut slot).await;
        assert!(!r.quorum && slot.state().is_none());
        assert_eq!(slot.status(Instant::now()), "bootstrapping");
        assert!(round(&urls, 1, &mut slot).await.installed, "the insecure override takes one");
    }

    #[tokio::test]
    async fn a_keystone_serving_broken_work_is_rejected() {
        let chain = Arc::new(Chain::with_len(0, 0, 40));
        let (a, b, liar) = (ShardMock::new(chain.clone()), ShardMock::new(chain.clone()), ShardMock::new(chain));
        liar.corrupt.store(true, Ordering::SeqCst);
        let urls = vec![serve(a).await, serve(b).await, serve(liar.clone()).await];
        let mut slot = ThinShardSlot::default();
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.quorum && r.installed, "{r:?}");
        assert_eq!(r.rejected, vec![urls[2].clone()]);
        // The liar and one honest Keystone are not a quorum of two.
        let mut slot = ThinShardSlot::default();
        let r = round(&[urls[0].clone(), urls[2].clone()], 2, &mut slot).await;
        assert!(!r.quorum && slot.state().is_none(), "{r:?}");
    }

    #[tokio::test]
    async fn a_lying_blocks_feed_after_sync_falls_back_to_the_honest_keystone() {
        let chain = Arc::new(Chain::with_len(0, 0, 30));
        let (honest, liar) = (ShardMock::new(chain.clone()), ShardMock::new(chain.clone()));
        let urls = vec![serve(honest.clone()).await, serve(liar.clone()).await];
        let mut slot = ThinShardSlot::default();
        assert!(round(&urls, 2, &mut slot).await.installed);
        let longer = Arc::new(grown(&chain, 5));
        honest.serve_chain(longer.clone());
        liar.serve_chain(longer);
        liar.corrupt.store(true, Ordering::SeqCst);
        let r = round(&urls, 1, &mut slot).await;
        assert!(r.quorum && r.installed, "{r:?}");
        assert_eq!(slot.state().unwrap().leaf_count(), 35);
        assert!(r.rejected.contains(&urls[1]), "{r:?}");
    }

    #[tokio::test]
    async fn a_reorg_at_the_same_height_starts_a_new_session() {
        let main_chain = Arc::new(Chain::with_len(0, 0, 30));
        let (a, b) = (ShardMock::new(main_chain.clone()), ShardMock::new(main_chain));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinShardSlot::default();
        round(&urls, 2, &mut slot).await;
        let before = slot.state().unwrap().root();
        let fork = Arc::new(Chain::with_len(0, 1, 30));
        a.serve_chain(fork.clone());
        b.serve_chain(fork);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed && r.quorum, "{r:?}");
        assert_ne!(slot.state().unwrap().root(), before);
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 2, "a new session, not blocks");
    }

    #[tokio::test]
    async fn a_gap_larger_than_the_limit_uses_a_session() {
        let chain = Arc::new(Chain::with_len(0, 0, 10));
        let (a, b) = (ShardMock::new(chain.clone()), ShardMock::new(chain.clone()));
        let urls = vec![serve(a.clone()).await, serve(b.clone()).await];
        let mut slot = ThinShardSlot::default();
        round(&urls, 2, &mut slot).await;
        let jump = MAX_CATCH_UP_BLOCKS + 5;
        let longer = Arc::new(grown(&chain, jump));
        a.serve_chain(longer.clone());
        b.serve_chain(longer);
        let r = round(&urls, 2, &mut slot).await;
        assert!(r.installed, "{r:?}");
        assert_eq!(slot.state().unwrap().leaf_count(), 10 + jump);
        assert_eq!(a.session_calls.load(Ordering::SeqCst), 2);
        assert_eq!(a.blocks_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_wrong_anchor_accepts_nothing() {
        let chain = Arc::new(Chain::with_len(0, 0, 40));
        let (a, b) = (ShardMock::new(chain.clone()), ShardMock::new(chain));
        let urls = vec![serve(a).await, serve(b).await];
        let wrong = crate::mmr_client::thin_shard::ShardAnchor { root: WeightedHash::from([6u8; 32]), ..test_anchor() };
        let mut slot = ThinShardSlot::default();
        let r = thin_shard_round(&reqwest::Client::new(), &urls, &test_params(0), wrong, 1, &mut slot).await;
        assert!(!r.quorum && slot.state().is_none(), "{r:?}");
        assert_eq!(r.rejected.len(), 2);
    }

    #[tokio::test]
    async fn a_keystone_serving_another_shards_blocks_is_rejected() {
        // Mined for shard 1, followed as shard 0: hash-sorting routes the work elsewhere.
        let other = Arc::new(Chain::with_len(1, 0, 20));
        let a = ShardMock::new(other);
        let urls = vec![serve(a).await];
        let mut slot = ThinShardSlot::default();
        let r = round(&urls, 1, &mut slot).await;
        assert!(!r.quorum && r.rejected.len() == 1, "{r:?}");
    }

    #[test]
    fn contains_follows_the_held_prev_roots() {
        use crate::mmr_client::thin_shard::ThinShardState;
        let c = Chain::with_len(0, 0, 30);
        let long = ThinShardState::from_session(test_params(0), test_anchor(), &c.session(16)).unwrap();
        let short_chain = Chain::with_len(0, 0, 28);
        let short = ThinShardState::from_session(test_params(0), test_anchor(), &short_chain.session(16)).unwrap();
        assert!(contains(&long, &short), "the longer chain holds the block after the shorter tip");
        assert!(!contains(&short, &long));
    }
}
