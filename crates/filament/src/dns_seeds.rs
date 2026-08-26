// crates/filament/src/dns_seeds.rs
//
// PD-INT-2 — DNS seed resolution (Layer 3 of peer discovery).
//
// For each configured seed hostname:
//   1. Query TXT records and honour `port=<u16>` when present.
//   2. Default to `DEFAULT_DNS_SEED_PORT` (8334 — Lattice/ShishaNet) when TXT
//      is absent or does not specify a port.
//   3. Resolve A/AAAA addresses and return `(ip, port)` tuples for PeerCache.
//
// Design reference: `filament_app/docs/PEER_DISCOVERY_PLAN.md` PD-INT-2

use crate::peer_cache::PeerCache;

/// Default ShishaNet P2P port when a DNS seed TXT record omits `port=`.
pub const DEFAULT_DNS_SEED_PORT: u16 = 8334;

/// Parse `port=<u16>` from a DNS TXT payload (semicolon-separated tokens).
pub fn parse_port_from_txt(txt: &str) -> Option<u16> {
    for token in txt.split(';').map(str::trim) {
        if let Some(rest) = token.strip_prefix("port=") {
            if let Ok(port) = rest.parse::<u16>() {
                if port > 0 {
                    return Some(port);
                }
            }
        }
    }
    None
}

/// First `port=` found across one or more TXT strings (each may be a chunk).
pub fn port_from_txt_strings(records: &[String]) -> Option<u16> {
    for rec in records {
        if let Some(port) = parse_port_from_txt(rec) {
            return Some(port);
        }
    }
    None
}

#[cfg(feature = "full-node")]
fn collect_txt_strings(response: &hickory_resolver::lookup::TxtLookup) -> Vec<String> {
    let mut records = Vec::new();
    for txt in response.iter() {
        let joined: String = txt
            .txt_data()
            .iter()
            .filter_map(|b| std::str::from_utf8(b).ok())
            .collect();
        if !joined.is_empty() {
            records.push(joined);
        }
        for chunk in txt.txt_data() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if !s.is_empty() {
                    records.push(s.to_string());
                }
            }
        }
    }
    records
}

#[cfg(feature = "full-node")]
async fn dns_seed_port(
    resolver: &hickory_resolver::TokioAsyncResolver,
    hostname: &str,
    default_port: u16,
) -> u16 {
    match resolver.txt_lookup(hostname).await {
        Ok(response) => port_from_txt_strings(&collect_txt_strings(&response))
            .unwrap_or(default_port),
        Err(_) => default_port,
    }
}

#[cfg(feature = "full-node")]
/// Resolve a DNS seed hostname to live `(host, port)` peers.
pub async fn resolve_dns_seed(
    seed: &str,
    default_port: u16,
) -> Result<Vec<(String, u16)>, String> {
    use hickory_resolver::TokioAsyncResolver;

    let hostname = seed.trim();
    if hostname.is_empty() {
        return Err("empty DNS seed hostname".into());
    }

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| format!("DNS resolver init: {e}"))?;

    let port = dns_seed_port(&resolver, hostname, default_port).await;

    let response = resolver
        .lookup_ip(hostname)
        .await
        .map_err(|e| format!("A/AAAA lookup failed: {e}"))?;

    let peers: Vec<(String, u16)> = response
        .iter()
        .map(|ip| (ip.to_string(), port))
        .collect();

    if peers.is_empty() {
        return Err("no A/AAAA records".into());
    }

    Ok(peers)
}

#[cfg(feature = "full-node")]
/// Resolve every configured DNS seed and write results into `PeerCache`.
/// Returns the number of `(host, port)` entries written.
pub async fn refresh_dns_seeds_into_cache(
    cache: &PeerCache,
    seeds: &[String],
    default_port: u16,
) -> usize {
    let mut written = 0usize;
    for seed in seeds {
        match resolve_dns_seed(seed, default_port).await {
            Ok(peers) => {
                for (host, port) in peers {
                    cache.mark_seen(&host, port);
                    written += 1;
                }
            }
            Err(e) => {
                log::warn!("DNS seed {seed}: {e}");
            }
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pd_int_2_parse_port_from_txt_simple() {
        assert_eq!(parse_port_from_txt("port=8334"), Some(8334));
    }

    #[test]
    fn pd_int_2_parse_port_from_txt_semicolon_separated() {
        assert_eq!(parse_port_from_txt("v=1;port=9333;network=testnet1"), Some(9333));
    }

    #[test]
    fn pd_int_2_parse_port_ignores_invalid() {
        assert_eq!(parse_port_from_txt("port=0"), None);
        assert_eq!(parse_port_from_txt("port=99999"), None);
        assert_eq!(parse_port_from_txt("no-port-here"), None);
    }

    #[test]
    fn pd_int_2_port_from_txt_strings_first_match() {
        let records = vec![
            "v=1".to_string(),
            "port=8334".to_string(),
        ];
        assert_eq!(port_from_txt_strings(&records), Some(8334));
    }

    #[test]
    fn pd_int_2_default_dns_seed_port_is_8334() {
        assert_eq!(DEFAULT_DNS_SEED_PORT, 8334);
    }
}
