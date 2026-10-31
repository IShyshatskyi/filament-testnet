//! What the chain endpoints and the desktop app show for the beacon and the shards.
//!
//! One place for both surfaces (the HTTP server and the Tauri commands), so they cannot disagree
//! about which state they read: with `thin_sync` on, the locally verified thin state
//! (`thin_sync.rs`); otherwise the older chain handlers.

use crate::mmr_client::chain_handler::ChainType;
use crate::mmr_client::multi_chain_client::{ChainSyncStatus, MultiChainClient};

/// One chain row. Hashes are lowercase hex, empty when nothing is known yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    /// 0 = beacon, shard `n` = `n + 1`.
    pub chain_id: u32,
    pub height: u32,
    pub tip_hash: String,
    pub mmr_root: String,
    /// `synced`, `syncing`, `bootstrapping`/`not_started`, `insufficient_peers`, `unsupported`, ...
    pub status: String,
}

/// Overall sync state of the beacon for the sync-status screen.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncView {
    pub phase: String,
    pub progress: f64,
    pub synced_height: u32,
    pub tip_height: u32,
    /// The chain is current and backed by enough Keystones.
    pub trusted: bool,
}

fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn status_name(s: &ChainSyncStatus) -> (&'static str, u32, u32) {
    match s {
        ChainSyncStatus::NotStarted => ("not_started", 0, 0),
        ChainSyncStatus::Syncing { current_height, target_height, .. } => ("syncing", *current_height, *target_height),
        ChainSyncStatus::Synced => ("synced", 0, 0),
        ChainSyncStatus::Error { .. } => ("error", 0, 0),
        ChainSyncStatus::Paused => ("paused", 0, 0),
        ChainSyncStatus::InsufficientPeers { .. } => ("insufficient_peers", 0, 0),
    }
}

/// The beacon row.
pub async fn beacon_view(client: &MultiChainClient, thin: bool) -> ChainView {
    #[cfg(feature = "full-node")]
    if thin {
        let slot = client.thin_beacon_slot().unwrap_or_default();
        let (hash, root) = match slot.state() {
            Some(st) => (
                st.tip().map(|h| hex::encode(h.pow_hash())).unwrap_or_default(),
                hex32(&<[u8; 32]>::from(crate::mmr_client::thin_chain::ThinState::root(st))),
            ),
            None => (String::new(), String::new()),
        };
        return ChainView {
            chain_id: 0,
            height: slot.tip_height(),
            tip_hash: hash,
            mmr_root: root,
            status: slot.status(std::time::Instant::now()).to_string(),
        };
    }
    let _ = thin;
    let status = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
    let (name, height, _) = status_name(&status);
    match client.get_beacon_state().await {
        Ok(s) => ChainView {
            chain_id: 0,
            height: s.height(),
            tip_hash: hex32(&s.tip_hash()),
            mmr_root: hex32(&s.mmr_root_bytes()),
            status: name.into(),
        },
        Err(_) => ChainView { chain_id: 0, height, tip_hash: String::new(), mmr_root: String::new(), status: name.into() },
    }
}

/// A followed shard from the thin state, `None` when thin sync does not follow it.
#[cfg(feature = "full-node")]
fn thin_shard_view(client: &MultiChainClient, shard_id: u16) -> Option<ChainView> {
    let t = client.thin_shard(shard_id)?;
    let (hash, root) = match t.slot.state() {
        Some(st) => (
            st.tip_hash().map(hex::encode).unwrap_or_default(),
            hex32(&<[u8; 32]>::from(crate::mmr_client::thin_chain::ThinState::root(st))),
        ),
        None => (String::new(), String::new()),
    };
    let status = match t.note {
        Some("unsupported_dynamic_shard") => "unsupported",
        Some("awaiting_anchor") => "bootstrapping",
        _ => t.slot.status(std::time::Instant::now()),
    };
    Some(ChainView {
        chain_id: u32::from(shard_id) + 1,
        height: t.slot.tip_height(),
        tip_hash: hash,
        mmr_root: root,
        status: status.to_string(),
    })
}

/// One shard row. With thin sync on, a followed shard is read from the thin state;
/// any other shard falls back to the older handler.
pub async fn shard_view(client: &MultiChainClient, shard_id: u32, thin: bool) -> ChainView {
    #[cfg(feature = "full-node")]
    if thin {
        if let Some(v) = u16::try_from(shard_id).ok().and_then(|id| thin_shard_view(client, id)) {
            return v;
        }
    }
    let _ = thin;
    let status = client.get_trusted_sync_status_for_shard(shard_id).await;
    let (name, height, _) = status_name(&status);
    match client.get_shard_state(shard_id).await {
        Ok(s) => ChainView {
            chain_id: shard_id + 1,
            height: s.height(),
            tip_hash: hex32(&s.tip_hash()),
            mmr_root: hex32(&s.mmr_root_bytes()),
            status: name.into(),
        },
        Err(_) => ChainView { chain_id: shard_id + 1, height, tip_hash: String::new(), mmr_root: String::new(), status: name.into() },
    }
}

/// The beacon followed by every shard the client knows (older handlers) and, with thin
/// sync on, every shard it follows.
pub async fn chain_views(client: &MultiChainClient, thin: bool) -> Vec<ChainView> {
    let mut rows = vec![beacon_view(client, thin).await];
    let mut ids: Vec<u32> = client.shard_ids();
    #[cfg(feature = "full-node")]
    if thin {
        for id in client.thin_shard_ids() {
            if !ids.contains(&u32::from(id)) {
                ids.push(u32::from(id));
            }
        }
    }
    ids.sort_unstable();
    for id in ids {
        rows.push(shard_view(client, id, thin).await);
    }
    rows
}

/// The sync-status screen's view of the beacon.
pub async fn sync_view(client: &MultiChainClient, thin: bool) -> SyncView {
    #[cfg(feature = "full-node")]
    if thin {
        let slot = client.thin_beacon_slot().unwrap_or_default();
        let h = slot.tip_height();
        return match slot.status(std::time::Instant::now()) {
            "synced" => SyncView { phase: "synced".into(), progress: 1.0, synced_height: h, tip_height: h, trusted: true },
            "insufficient_peers" => {
                SyncView { phase: "insufficient_peers".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false }
            }
            _ => SyncView { phase: "not_started".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false },
        };
    }
    let _ = thin;
    let status = client.get_trusted_sync_status(ChainType::Beacon, 0).await;
    match &status {
        ChainSyncStatus::NotStarted => SyncView { phase: "not_started".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false },
        ChainSyncStatus::Syncing { current_height, target_height, progress_percent } => SyncView {
            phase: "syncing".into(),
            progress: *progress_percent as f64 / 100.0,
            synced_height: *current_height,
            tip_height: *target_height,
            trusted: false,
        },
        ChainSyncStatus::Synced => {
            let h = client.get_beacon_state().await.map(|s| s.height()).unwrap_or(0);
            SyncView { phase: "synced".into(), progress: 1.0, synced_height: h, tip_height: h, trusted: true }
        }
        ChainSyncStatus::Error { .. } => SyncView { phase: "error".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false },
        ChainSyncStatus::Paused => SyncView { phase: "paused".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false },
        ChainSyncStatus::InsufficientPeers { .. } => {
            SyncView { phase: "insufficient_peers".into(), progress: 0.0, synced_height: 0, tip_height: 0, trusted: false }
        }
    }
}

#[cfg(all(test, feature = "full-node"))]
mod tests {
    use super::*;
    use crate::mmr_client::thin_chain::tests::{build_proving, session, ANCHOR};
    use crate::mmr_client::thin_chain::{ThinBeaconState, ThinState};
    use crate::mmr_client::thin_shard::tests::{test_anchor, test_params, Chain};
    use crate::mmr_client::thin_shard::ThinShardState;
    use crate::mmr_client::thin_sync::{ShardThin, ThinBeaconSlot, ThinShardSlot};
    use std::time::Instant;

    fn client() -> MultiChainClient {
        MultiChainClient::new(Box::new(crate::mmr_client::storage::InMemoryStorage::new()))
    }

    fn beacon_slot(n: u32) -> (ThinBeaconSlot, ThinBeaconState) {
        let (hs, win) = build_proving(n);
        let st = ThinBeaconState::from_session(ANCHOR, [0xFF; 32], 1, &session(&hs, &win, 16)).unwrap();
        let mut slot = ThinBeaconSlot::default();
        slot.install(st.clone(), Instant::now());
        (slot, st)
    }

    #[tokio::test]
    async fn the_beacon_row_reads_the_thin_state() {
        let mut c = client();
        let (slot, st) = beacon_slot(40);
        c.set_thin_beacon_slot(slot);
        let v = beacon_view(&c, true).await;
        assert_eq!((v.chain_id, v.height, v.status.as_str()), (0, 39, "synced"));
        assert_eq!(v.mmr_root, hex::encode(<[u8; 32]>::from(st.root())));
        assert_eq!(v.tip_hash, hex::encode(st.tip().unwrap().pow_hash()));
        // The same client read the old way knows nothing: the views are not interchangeable.
        let old = beacon_view(&c, false).await;
        assert_eq!(old.height, 0);
        assert_ne!(old.status, "synced");
    }

    #[tokio::test]
    async fn followed_shards_are_listed_after_the_beacon_and_unsupported_ones_say_so() {
        let mut c = client();
        c.set_thin_beacon_slot(beacon_slot(40).0);
        let chain = Chain::with_len(0, 0, 20);
        let st = ThinShardState::from_session(test_params(0), test_anchor(), &chain.session(16)).unwrap();
        let mut slot = ThinShardSlot::default();
        slot.install(st.clone(), Instant::now());
        c.set_thin_shard(0, ShardThin { slot, anchor: Some(test_anchor()), note: None });
        c.set_thin_shard(9, ShardThin { note: Some("unsupported_dynamic_shard"), ..ShardThin::default() });

        let rows = chain_views(&c, true).await;
        assert_eq!(rows.iter().map(|r| r.chain_id).collect::<Vec<_>>(), vec![0, 1, 10]);
        assert_eq!((rows[1].height, rows[1].status.as_str()), (19, "synced"));
        assert_eq!(rows[1].mmr_root, hex::encode(<[u8; 32]>::from(st.root())));
        assert_eq!(rows[1].tip_hash, hex::encode(st.tip_hash().unwrap()));
        assert_eq!(rows[2].status, "unsupported");
        assert_eq!(shard_view(&c, 0, true).await, rows[1]);

        // Thin sync off: the shards are not listed from the thin state.
        assert_eq!(chain_views(&c, false).await.len(), 1);
    }

    #[tokio::test]
    async fn the_sync_screen_follows_the_thin_beacon() {
        let mut c = client();
        let v = sync_view(&c, true).await;
        assert_eq!((v.phase.as_str(), v.trusted), ("not_started", false));
        c.set_thin_beacon_slot(beacon_slot(40).0);
        let v = sync_view(&c, true).await;
        assert_eq!((v.phase.as_str(), v.synced_height, v.tip_height, v.trusted), ("synced", 39, 39, true));
        assert_eq!(v.progress, 1.0);
    }
}
