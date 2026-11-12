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
        // A host the operator already configured a REST endpoint for has told us its REST port.
        // Guessing `keystone_rest_port` for it adds an endpoint nothing listens on and every sync cycle
        // then polls it for nothing. The same holds for a loopback peer when the operator configured a
        // loopback REST endpoint: all of 127.0.0.0/8 is this machine, and a local multi-node setup runs REST on
        // 127.0.0.1:18081/18082 with the P2P peers on 127.0.0.21/.22, so no exact host match can find
        // them (a guessed port on those loopback peers was polled forever).
        let configured_loopback = configured.iter().filter_map(|ep| endpoint_host(ep)).any(is_loopback_host);
        if configured.iter().any(|ep| endpoint_host(ep) == Some(host.as_str()))
            || (is_loopback_host(&host) && configured_loopback)
        {
            continue;
        }
        let url = format!("http://{host}:{keystone_rest_port}");
        if !eps.contains(&url) {
            eps.push(url);
        }
    }
    eps
}

/// True for `localhost` and any literal 127.0.0.0/8 or ::1 address.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().map_or(false, |ip| ip.is_loopback())
}

/// Host part of a `scheme://host[:port][/path]` endpoint (bracketed IPv6 keeps its brackets off).
fn endpoint_host(endpoint: &str) -> Option<&str> {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let authority = rest.split('/').next()?;
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    (!host.is_empty()).then_some(host)
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

    // A manual P2P peer on a host that already has a configured REST endpoint must not add a
    // guessed `http://host:7379` (a phantom :7379 poll); a different host still does.
    #[test]
    fn pd_int_2_configured_rest_host_is_not_guessed_again() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        let configured = vec!["http://127.0.0.21:18081".to_string()];
        let manual = vec![("127.0.0.21".to_string(), 18344u16), ("keystone2.example".to_string(), 18346u16)];
        let eps = merge_discovery_keystone_endpoints(&configured, &cache, &manual, &[], "testnet1", 7379);
        assert!(!eps.contains(&"http://127.0.0.21:7379".to_string()), "{eps:?}");
        assert!(eps.contains(&"http://127.0.0.21:18081".to_string()), "{eps:?}");
        assert!(eps.contains(&"http://keystone2.example:7379".to_string()), "{eps:?}");
    }

    // A local multi-node shape: REST configured on 127.0.0.1, manual P2P peers on other loopback
    // addresses. No host matches, yet no :7379 guess may be added for the manual peers.
    #[test]
    fn pd_int_3_loopback_peers_are_not_guessed_when_loopback_rest_is_configured() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        let configured = vec!["http://127.0.0.1:18081".to_string(), "http://127.0.0.1:18082".to_string()];
        let manual = vec![("127.0.0.21".to_string(), 18344u16), ("127.0.0.22".to_string(), 18346u16)];
        let eps = merge_discovery_keystone_endpoints(&configured, &cache, &manual, &[], "testnet-stress", 7379);
        assert_eq!(eps, configured, "{eps:?}");
    }

    // Without configured REST endpoints a manual peer still yields the default-port guess.
    #[test]
    fn pd_int_4_manual_peers_are_guessed_when_no_rest_is_configured() {
        let dir = TempDir::new().unwrap();
        let cache = empty_cache(dir.path());
        let manual = vec![("my-node.example.com".to_string(), 9333u16)];
        let eps = merge_discovery_keystone_endpoints(&[], &cache, &manual, &[], "testnet1", 7379);
        assert!(eps.contains(&"http://my-node.example.com:7379".to_string()), "{eps:?}");
    }

    #[test]
    fn loopback_hosts_are_recognised() {
        assert!(is_loopback_host("127.0.0.1") && is_loopback_host("127.0.0.22") && is_loopback_host("::1") && is_loopback_host("localhost"));
        assert!(!is_loopback_host("10.0.0.1") && !is_loopback_host("keystone2.example"));
    }

    #[test]
    fn endpoint_host_parses_scheme_port_path_and_ipv6() {
        assert_eq!(endpoint_host("http://127.0.0.21:18081"), Some("127.0.0.21"));
        assert_eq!(endpoint_host("https://keystone.example/api"), Some("keystone.example"));
        assert_eq!(endpoint_host("keystone.example:7379"), Some("keystone.example"));
        assert_eq!(endpoint_host("http://[::1]:7379"), Some("::1"));
        assert_eq!(endpoint_host("http://"), None);
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
