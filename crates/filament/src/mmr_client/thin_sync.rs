//! Thin beacon sync loop (`docs/plan/Filament_Thin_Sync_Design.md` §3, §9).
//!
//! Public packaging ships the **beacon** round only. Shard thin-sync stays in
//! the monorepo until `FullShardHeader` / `verify_shard_id_and_mmn` are
//! allowlisted into filament-types (no private engines).
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

use common_types::common::proofs::{ThinHeadersResponse, ThinSessionResponse, ThinTipResponse};
use futures_util::FutureExt;
use serde::de::DeserializeOwned;

use crate::mmr_client::thin_chain::{plan_sync, SyncAction, ThinBeaconState, ThinState, RECENT_HEADERS};

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
#[allow(dead_code)] // reserved for thin_shard catch-up once types-port lands
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




