// crates/filament/src/peer_cache.rs
//
// PD-1 — Peer cache: `peers.json` atomic read/write; 7-day entry expiry.
//
// Layer 1 of Filament peer discovery (fastest path — previously-connected
// nodes).  Entries that haven't been seen in 7 days are silently dropped
// on the next load.
//
// Design reference: `filament_app/docs/PEER_DISCOVERY_PLAN.md` §2

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// 7 days in milliseconds
const EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

// ─── PeerEntry ───────────────────────────────────────────────────────────────

/// A single cached peer address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub host:         String,
    pub port:         u16,
    /// Unix timestamp (ms) of the last successful connection.
    pub last_seen_ms: u64,
}

impl PeerEntry {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port, last_seen_ms: now_ms() }
    }

    pub fn is_stale(&self) -> bool {
        now_ms().saturating_sub(self.last_seen_ms) > EXPIRY_MS
    }
}

// ─── PeerCache ───────────────────────────────────────────────────────────────

/// Atomic JSON-file peer cache.
///
/// Writes go to `.peers.json.tmp` then `rename()` — crash-safe.
pub struct PeerCache {
    path: PathBuf,
}

impl PeerCache {
    /// Open (or create) the peer cache at `<base_dir>/peers.json`.
    pub fn open(base_dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(base_dir)?;
        Ok(Self { path: base_dir.join("peers.json") })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_all(&self) -> Vec<PeerEntry> {
        if !self.path.exists() {
            return Vec::new();
        }
        let data = match fs::read(&self.path) {
            Ok(d)  => d,
            Err(_) => return Vec::new(),
        };
        serde_json::from_slice::<Vec<PeerEntry>>(&data).unwrap_or_default()
    }

    fn save_all(&self, entries: &[PeerEntry]) {
        let tmp = self.path.with_file_name(".peers.json.tmp");
        if let Ok(data) = serde_json::to_vec_pretty(entries) {
            let _ = fs::write(&tmp, &data);
            let _ = fs::rename(&tmp, &self.path);
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Return all non-stale cached peers in most-recently-seen order.
    pub fn live_peers(&self) -> Vec<(String, u16)> {
        let mut entries: Vec<PeerEntry> = self
            .load_all()
            .into_iter()
            .filter(|e| !e.is_stale())
            .collect();
        // Most recently seen first.
        entries.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        entries.into_iter().map(|e| (e.host, e.port)).collect()
    }

    /// Record a successful connection.  If the host+port already exists the
    /// `last_seen_ms` is updated in-place; otherwise a new entry is appended.
    pub fn mark_seen(&self, host: &str, port: u16) {
        let mut entries = self.load_all();
        if let Some(e) = entries.iter_mut().find(|e| e.host == host && e.port == port) {
            e.last_seen_ms = now_ms();
        } else {
            entries.push(PeerEntry::new(host, port));
        }
        self.save_all(&entries);
    }

    /// Explicitly remove a peer (used when the user removes a peer from the
    /// settings UI or when the peer is permanently unreachable).
    pub fn remove(&self, host: &str, port: u16) {
        let mut entries = self.load_all();
        entries.retain(|e| !(e.host == host && e.port == port));
        self.save_all(&entries);
    }

    /// Drop all entries whose `last_seen_ms` is older than 7 days.
    pub fn evict_stale(&self) {
        let entries: Vec<PeerEntry> = self.load_all().into_iter().filter(|e| !e.is_stale()).collect();
        self.save_all(&entries);
    }

    /// Total number of cached entries (including stale ones).
    pub fn len(&self) -> usize {
        self.load_all().len()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Tests (PD-T-1 / PD-T-2) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_cache() -> (TempDir, PeerCache) {
        let dir = TempDir::new().unwrap();
        let cache = PeerCache::open(dir.path()).unwrap();
        (dir, cache)
    }

    // PD-T-1
    #[test]
    fn peer_cache_add_and_retrieve() {
        let (_dir, cache) = tmp_cache();
        cache.mark_seen("node1.example.com", 8333);
        cache.mark_seen("192.0.2.1", 8334);
        let live = cache.live_peers();
        assert_eq!(live.len(), 2);
        // Most recently added — could be either order by ms; just check both present
        assert!(live.iter().any(|(h, p)| h == "node1.example.com" && *p == 8333));
        assert!(live.iter().any(|(h, p)| h == "192.0.2.1" && *p == 8334));
    }

    // PD-T-2: stale entry (last_seen_ms set to > 7 days ago) is not returned
    #[test]
    fn peer_cache_evicts_stale_entries() {
        let (_dir, cache) = tmp_cache();

        // Insert a fresh entry and a stale one by writing raw JSON.
        let stale_ms = now_ms().saturating_sub(EXPIRY_MS + 1_000);
        let entries = vec![
            PeerEntry { host: "fresh.example.com".into(), port: 8333, last_seen_ms: now_ms() },
            PeerEntry { host: "stale.example.com".into(), port: 8333, last_seen_ms: stale_ms },
        ];
        cache.save_all(&entries);

        let live = cache.live_peers();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, "fresh.example.com");
    }

    #[test]
    fn peer_cache_update_last_seen_on_duplicate() {
        let (_dir, cache) = tmp_cache();
        cache.mark_seen("node.example.com", 8333);
        cache.mark_seen("node.example.com", 8333); // second call — update, not duplicate
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn peer_cache_remove() {
        let (_dir, cache) = tmp_cache();
        cache.mark_seen("node.example.com", 8333);
        cache.remove("node.example.com", 8333);
        assert!(cache.live_peers().is_empty());
    }
}
