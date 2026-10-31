// src/full_node/notification_ring.rs
//
// Operator-facing structured alert feed for the Octopus full node.
//
// This is distinct from the raw log ring (`log_ring.rs`):
//
// | Property        | LogRing (`GET /logs`)          | NotifRing (`GET /notifications`)  |
// |-----------------|-------------------------------|-----------------------------------|
// | Volume          | High (hundreds/hour)           | Low (tens/day)                    |
// | Consumer        | Developers debugging           | Operators monitoring               |
// | Routing         | Passive tracing intercept      | Explicit `notify()` call sites    |
// | Lifetime        | Ring evicts after 500          | Ring evicts after 200; browser     |
// |                 |                                | localStorage persists dismissal   |
// | Actions         | Read-only                      | Dismiss, jump-to-view             |
//
// # Design constraints
//
// * All methods are synchronous (`Mutex`, not `tokio::Mutex`) — `notify()` is
//   called from hot async paths and must not introduce await-point overhead.
// * `try_lock()` is NOT used here because `notify()` is not on the tracing
//   callsite fast path. A brief lock contention in `notify()` is acceptable.
// * `GET /notifications` reads the ring under lock and clones the result.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Maximum notifications kept in the ring (oldest evicted when full).
pub const MAX_NOTIF_ENTRIES: usize = 200;

// ─── Data model ──────────────────────────────────────────────────────────────

/// Semantic severity of a notification.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotifSeverity {
    /// Immediate operator action required; badge turns red.
    Critical,
    /// Degraded operation; badge turns amber.
    Warn,
    /// Informational milestone; badge shown in muted colour.
    Info,
}

impl NotifSeverity {
    /// Case-insensitive match against the string form used in query params.
    pub fn matches_str(&self, s: &str) -> bool {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => *self == NotifSeverity::Critical,
            "WARN"     => *self == NotifSeverity::Warn,
            "INFO"     => *self == NotifSeverity::Info,
            _          => false,
        }
    }
}

/// Logical source of a notification.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotifCategory {
    Chain,    // fork detection, reorg, epoch boundary
    P2p,      // peer ban, low peers, isolated, bootstrap
    Storage,  // checkpoint, epoch migration, WAL depth, disk-full
    Sync,     // sync start/complete/stall/disagreement
    System,   // startup, shutdown, config reload, memory threshold
    Proof,    // proof serve errors, verification failures
}

impl NotifCategory {
    /// Case-insensitive match against the string form used in query params.
    pub fn matches_str(&self, s: &str) -> bool {
        match s.to_ascii_lowercase().as_str() {
            "chain"   => *self == NotifCategory::Chain,
            "p2p"     => *self == NotifCategory::P2p,
            "storage" => *self == NotifCategory::Storage,
            "sync"    => *self == NotifCategory::Sync,
            "system"  => *self == NotifCategory::System,
            "proof"   => *self == NotifCategory::Proof,
            _         => false,
        }
    }
}

/// Which Octopus UI view to navigate to when the user clicks "Go to".
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "view", rename_all = "snake_case")]
pub enum NotifViewHint {
    /// Navigate to the Chains view; optionally highlight a specific chain.
    Chains { chain_id: Option<String> },
    /// Navigate to the Peers view; optionally highlight a specific peer.
    Peers { peer_id: Option<String> },
    /// Navigate to the Storage view.
    Storage,
    /// Navigate to the Logs view and pre-fill the search filter.
    Logs { filter: Option<String> },
    /// Navigate to the Proofs view.
    Proofs,
}

/// A single operator-facing alert event.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NotificationEvent {
    /// Monotonically increasing 1-based ID. Allows clients to poll with `?since=id`.
    pub id: u64,

    /// Unix milliseconds at emission time.
    pub ts_ms: u64,

    /// Semantic severity.
    pub severity: NotifSeverity,

    /// Source category.
    pub category: NotifCategory,

    /// Short human-readable headline (< 80 chars). Shown in the sidebar badge
    /// tooltip and notification list row.
    pub title: String,

    /// Optional longer detail string. Shown when the row is expanded. May
    /// contain hex hashes, heights, file paths, or error messages.
    pub body: Option<String>,

    /// Optional jump-to-view hint for the frontend.
    pub view_hint: Option<NotifViewHint>,
}

// ─── Ring ─────────────────────────────────────────────────────────────────────

/// Thread-safe notification ring buffer.
///
/// Clone-cheaply via the inner `Arc`.
#[derive(Clone)]
pub struct NotifRing {
    inner: Arc<Mutex<NotifRingInner>>,
}

struct NotifRingInner {
    entries:  VecDeque<NotificationEvent>,
    next_id:  u64,
    capacity: usize,
}

impl NotifRing {
    /// Create a new ring with the given capacity.
    pub fn new(capacity: usize) -> Self {
        NotifRing {
            inner: Arc::new(Mutex::new(NotifRingInner {
                entries:  VecDeque::with_capacity(capacity.min(MAX_NOTIF_ENTRIES)),
                next_id:  1,
                capacity: capacity.min(MAX_NOTIF_ENTRIES),
            })),
        }
    }

    /// Append a new notification.
    ///
    /// Evicts the oldest entry when at capacity. Returns the assigned `id`.
    pub fn notify(
        &self,
        severity:  NotifSeverity,
        category:  NotifCategory,
        title:     impl Into<String>,
        body:      Option<String>,
        view_hint: Option<NotifViewHint>,
    ) -> u64 {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = inner.next_id;
        inner.next_id += 1;

        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(NotificationEvent {
            id,
            ts_ms,
            severity,
            category,
            title: title.into(),
            body,
            view_hint,
        });
        id
    }

    /// Return all entries with `id > since`, newest first, up to `limit`.
    pub fn since(&self, since: u64, limit: usize) -> Vec<NotificationEvent> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .entries
            .iter()
            .rev()
            .filter(|e| e.id > since)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Count of CRITICAL entries with `id > since` (for topbar badge polling).
    pub fn critical_count_since(&self, since: u64) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .entries
            .iter()
            .filter(|e| e.id > since && e.severity == NotifSeverity::Critical)
            .count()
    }

    /// Total number of entries currently in the ring.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.len()
    }

    /// The ID that will be assigned to the next notification.
    pub fn next_id(&self) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.next_id
    }
}

/// Convenience type alias. `NotifHandle` can be cloned into `ApiState` and
/// subsystem constructors cheaply because the `Arc` makes it pointer-sized.
pub type NotifHandle = NotifRing;

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(ring: &NotifRing, title: &str) -> u64 {
        ring.notify(
            NotifSeverity::Info,
            NotifCategory::System,
            title.to_owned(),
            None,
            None,
        )
    }

    #[test]
    fn notif_ring_appends_and_retrieves() {
        let ring = NotifRing::new(10);
        let id1 = make_info(&ring, "first");
        let id2 = make_info(&ring, "second");
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(ring.len(), 2);

        // `since(0)` returns all entries newest-first
        let entries = ring.since(0, 100);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 2); // newest first
        assert_eq!(entries[0].title, "second");
        assert_eq!(entries[1].id, 1);
    }

    #[test]
    fn notif_ring_since_filters_by_id() {
        let ring = NotifRing::new(10);
        make_info(&ring, "a"); // id=1
        make_info(&ring, "b"); // id=2
        make_info(&ring, "c"); // id=3

        let new = ring.since(2, 100); // only id=3
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].title, "c");
    }

    #[test]
    fn notif_ring_evicts_oldest_when_full() {
        let capacity = 3;
        let ring = NotifRing::new(capacity);
        make_info(&ring, "a"); // id=1  ← will be evicted
        make_info(&ring, "b"); // id=2
        make_info(&ring, "c"); // id=3
        make_info(&ring, "d"); // id=4: "a" evicted

        assert_eq!(ring.len(), capacity);
        let all = ring.since(0, 100);
        // ids 2,3,4 remain; newest first
        assert_eq!(all[0].id, 4);
        assert_eq!(all[1].id, 3);
        assert_eq!(all[2].id, 2);
    }

    #[test]
    fn notif_ring_critical_count_since() {
        let ring = NotifRing::new(10);
        ring.notify(NotifSeverity::Critical, NotifCategory::Chain, "fork!", None, None); // id=1
        ring.notify(NotifSeverity::Warn,     NotifCategory::P2p,   "low",  None, None); // id=2
        ring.notify(NotifSeverity::Critical, NotifCategory::Storage,"disk full", None, None); // id=3

        assert_eq!(ring.critical_count_since(0), 2);
        assert_eq!(ring.critical_count_since(1), 1); // only id=3
        assert_eq!(ring.critical_count_since(3), 0); // none after id=3
    }

    #[test]
    fn notif_severity_matches_str() {
        assert!(NotifSeverity::Critical.matches_str("CRITICAL"));
        assert!(NotifSeverity::Critical.matches_str("critical"));
        assert!(!NotifSeverity::Critical.matches_str("WARN"));
        assert!(NotifSeverity::Warn.matches_str("warn"));
        assert!(NotifSeverity::Info.matches_str("INFO"));
    }

    #[test]
    fn notif_category_matches_str() {
        assert!(NotifCategory::Chain.matches_str("chain"));
        assert!(NotifCategory::P2p.matches_str("P2P"));
        assert!(NotifCategory::Storage.matches_str("STORAGE"));
        assert!(!NotifCategory::System.matches_str("chain"));
    }

    #[test]
    fn notif_ring_limit_respected() {
        let ring = NotifRing::new(20);
        for i in 0..10 {
            make_info(&ring, &format!("msg {}", i));
        }
        let limited = ring.since(0, 3);
        assert_eq!(limited.len(), 3);
        // newest first
        assert_eq!(limited[0].id, 10);
    }

    #[test]
    fn notif_ring_view_hint_serialises() {
        let ring = NotifRing::new(5);
        ring.notify(
            NotifSeverity::Critical,
            NotifCategory::Chain,
            "Fork at 12345",
            Some("hashes diverged".into()),
            Some(NotifViewHint::Chains { chain_id: Some("beacon".into()) }),
        );
        let entries = ring.since(0, 1);
        assert_eq!(entries.len(), 1);
        let json = serde_json::to_string(&entries[0]).unwrap();
        assert!(json.contains("\"view\":\"chains\""), "view_hint not serialised");
        assert!(json.contains("\"chain_id\":\"beacon\""), "chain_id missing");
    }
}
