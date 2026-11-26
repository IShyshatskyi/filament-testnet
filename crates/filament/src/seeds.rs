// crates/filament/src/seeds.rs
//
// PD-4 — Compile-time hardcoded seed list (Layer 4 of peer discovery).
// Last resort: used only when cache, manual peers, and DNS all yield nothing.
//
// No seed nodes exist yet, so both lists are empty: Filament then needs `--keystone` or a
// manual peer. Add only hosts the project owns and has set up (`hcrn.net`); a default name
// under a domain someone else can register hands that person the peers Filament trusts.

/// Mainnet bootstrap seed nodes (none yet).
pub const MAINNET_SEEDS: &[(&str, u16)] = &[];

/// Testnet bootstrap seed nodes (none yet).
pub const TESTNET_SEEDS: &[(&str, u16)] = &[];

/// A domain that earlier builds used as a default although the project never owned it. Saved
/// settings and peer caches may still name it, so it is dropped wherever peers are gathered.
const RETIRED_SEED_DOMAIN: &str = "shishanet.io";

/// Is `host` the retired seed domain or a name under it?
pub fn is_retired_seed_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.strip_suffix(RETIRED_SEED_DOMAIN)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// Return the correct seed list for the given network identifier.
/// Recognises `"mainnet"`, `"testnet1"`, `"testnet2"`, `"testnet-stress"`;
/// everything else returns `TESTNET_SEEDS`.
pub fn seeds_for_network(network: &str) -> &'static [(&'static str, u16)] {
    match network {
        "mainnet" => MAINNET_SEEDS,
        _         => TESTNET_SEEDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_seeds_are_only_under_the_project_domain() {
        for (host, _) in MAINNET_SEEDS.iter().chain(TESTNET_SEEDS) {
            assert!(host.ends_with(".hcrn.net"), "{host}");
        }
    }

    #[test]
    fn the_retired_domain_is_recognised() {
        for host in ["shishanet.io", "seed1.shishanet.io", "Testnet-Seeds.ShishaNet.IO.", "a.b.shishanet.io"] {
            assert!(is_retired_seed_host(host), "{host}");
        }
        for host in ["notshishanet.io", "shishanet.io.example", "seed1.hcrn.net", "127.0.0.1", ""] {
            assert!(!is_retired_seed_host(host), "{host}");
        }
    }
}
