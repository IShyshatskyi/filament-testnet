// crates/filament/src/peer_discovery.rs
//
// PD-3 — Four-layer peer discovery for the Filament light client.
//
// Priority (highest → lowest):
//   Layer 1  Cached peers     (live_peers from PeerCache)
//   Layer 2  Manual peers     (user-added via settings or node QR scan)
//   Layer 3  DNS seeds        (async; not part of synchronous resolve())
//   Layer 4  Hardcoded seeds  (compile-time fallback in crate::seeds)
//
// The synchronous `resolve()` method covers Layers 1, 2, and 4.
// DNS (Layer 3) is resolved asynchronously by the filament_server background
// task, which writes results into PeerCache (Layer 1) via `mark_seen`.
//
// Design reference: `filament_app/docs/PEER_DISCOVERY_PLAN.md` §2

use crate::peer_cache::PeerCache;
use crate::seeds;

/// Four-layer peer resolver.
pub struct PeerDiscovery<'a> {
    cache:       &'a PeerCache,
    manual:      &'a [(String, u16)],
    dns_seeds:   &'a [String],
    network:     &'a str,
}

impl<'a> PeerDiscovery<'a> {
    pub fn new(
        cache:     &'a PeerCache,
        manual:    &'a [(String, u16)],
        dns_seeds: &'a [String],
        network:   &'a str,
    ) -> Self {
        Self { cache, manual, dns_seeds, network }
    }

    /// Synchronous resolution: Layer 1 (cache) + Layer 2 (manual) with
    /// Layer 4 (hardcoded) as final fallback when both are empty.
    ///
    /// Returns peers in priority order, deduplicated by (host, port).
    pub fn resolve(&self) -> Vec<(String, u16)> {
        let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
        let mut result: Vec<(String, u16)> = Vec::new();

        // Layer 1 — cached peers (most-recently-seen first)
        for (host, port) in self.cache.live_peers() {
            if seen.insert((host.clone(), port)) {
                result.push((host, port));
            }
        }

        // Layer 2 — manual peers
        for (host, port) in self.manual {
            if seen.insert((host.clone(), *port)) {
                result.push((host.clone(), *port));
            }
        }

        // Layers 1+2 satisfied → done
        if !result.is_empty() {
            return result;
        }

        // Layer 4 — hardcoded seeds (last resort; Layer 3 / DNS is async)
        for (host, port) in seeds::seeds_for_network(self.network) {
            result.push((host.to_string(), *port));
        }
        result
    }

    /// DNS seed hostnames that should be resolved by the async caller
    /// (Layer 3).  The caller is expected to try these only when
    /// `resolve()` returns an empty list or all connections fail.
    pub fn dns_seed_hostnames(&self) -> &[String] {
        self.dns_seeds
    }
}

/// Synchronous peer list from Layers 1, 2, and 4 (see `PeerDiscovery::resolve`).
pub fn resolve_discovery_peers(
    cache:     &PeerCache,
    manual:    &[(String, u16)],
    dns_seeds: &[String],
    network:   &str,
) -> Vec<(String, u16)> {
    PeerDiscovery::new(cache, manual, dns_seeds, network).resolve()
}

/// Merge peer-discovery results into the configured Keystone REST endpoint list.
///
/// Each resolved peer contributes `http://{host}:{rest_port}`. The discovery
/// tuple's port is ignored for REST URL construction — hardcoded seeds advertise
/// ShishaNet P2P ports (8333), not Keystone wallet REST (7379 by default).
pub fn merge_discovery_keystone_endpoints(
    configured:         &[String],
    cache:              &PeerCache,
    manual:             &[(String, u16)],
    dns_seeds:          &[String],
    network:            &str,
    keystone_rest_port: u16,
) -> Vec<String> {
    let mut eps: Vec<String> = configured.to_vec();
    for (host, _) in resolve_discovery_peers(cache, manual, dns_seeds, network) {
        let url = format!("http://{host}:{keystone_rest_port}");
        if !eps.contains(&url) {
            eps.push(url);
        }
    }
    eps
}

// ─── Tests (PD-T-3 / PD-T-4) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_cache::PeerCache;
    use tempfile::TempDir;

    fn empty_cache(dir: &std::path::Path) -> PeerCache {
        PeerCache::open(dir).unwrap()
    }

    // PD-T-3: when manual peers are configured, they appear in the result
    // (before hardcoded seeds, confirming they take priority over Layer 4).
    #[test]
    fn peer_discovery_manual_takes_priority() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path()); // empty cache
        let manual = vec![("my-node.example.com".to_string(), 9333u16)];
        let dns: Vec<String> = vec![];

        let discovery = PeerDiscovery::new(&cache, &manual, &dns, "testnet1");
        let peers = discovery.resolve();

        // Manual peer is returned and it is NOT a hardcoded seed.
        assert!(peers.iter().any(|(h, p)| h == "my-node.example.com" && *p == 9333));
        // Hardcoded testnet seeds are NOT included because manual satisfied the list.
        let hardcoded_host = seeds::TESTNET_SEEDS[0].0;
        assert!(!peers.iter().any(|(h, _)| h == hardcoded_host));
    }

    // PD-T-4: empty cache + no manual peers → hardcoded seeds returned.
    #[test]
    fn peer_discovery_falls_back_to_hardcoded() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        let manual: Vec<(String, u16)> = vec![];
        let dns: Vec<String> = vec![];

        let discovery = PeerDiscovery::new(&cache, &manual, &dns, "testnet1");
        let peers = discovery.resolve();

        assert!(!peers.is_empty());
        // First result should be a testnet hardcoded seed.
        let hardcoded_host = seeds::TESTNET_SEEDS[0].0;
        assert!(peers.iter().any(|(h, _)| h == hardcoded_host));
    }

    // PD-INT-1: empty explicit config → hardcoded seeds appear as REST URLs.
    #[test]
    fn pd_int_1_empty_config_includes_hardcoded_seed_endpoints() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        let eps = merge_discovery_keystone_endpoints(
            &[],
            &cache,
            &[],
            &[],
            "testnet1",
            7379,
        );
        assert!(!eps.is_empty());
        let hardcoded_host = seeds::TESTNET_SEEDS[0].0;
        assert!(
            eps.iter().any(|url| url == &format!("http://{hardcoded_host}:7379")),
            "expected hardcoded seed REST URL, got {eps:?}"
        );
    }

    #[test]
    fn cached_peers_appear_before_manual() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        cache.mark_seen("cached.example.com", 8333);

        let manual = vec![("manual.example.com".to_string(), 8333u16)];
        let dns: Vec<String> = vec![];

        let discovery = PeerDiscovery::new(&cache, &manual, &dns, "testnet1");
        let peers = discovery.resolve();

        assert_eq!(peers[0].0, "cached.example.com");
        assert!(peers.iter().any(|(h, _)| h == "manual.example.com"));
    }
}
