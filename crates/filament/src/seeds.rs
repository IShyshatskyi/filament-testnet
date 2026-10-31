// crates/filament/src/seeds.rs
//
// PD-4 — Compile-time hardcoded seed list (Layer 4 of peer discovery).
// Updated with every release.  Last resort: used only when cache, manual
// peers, and DNS all yield nothing.

/// Mainnet bootstrap seed nodes.
pub const MAINNET_SEEDS: &[(&str, u16)] = &[
    ("seed1.shishanet.io", 8333),
    ("seed2.shishanet.io", 8333),
];

/// Testnet bootstrap seed nodes.
pub const TESTNET_SEEDS: &[(&str, u16)] = &[
    ("testnet-seed1.shishanet.io", 8333),
    ("testnet-seed2.shishanet.io", 8333),
];

/// Return the correct seed list for the given network identifier.
/// Recognises `"mainnet"`, `"testnet1"`, `"testnet2"`, `"testnet-stress"`;
/// everything else returns `TESTNET_SEEDS`.
pub fn seeds_for_network(network: &str) -> &'static [(&'static str, u16)] {
    match network {
        "mainnet" => MAINNET_SEEDS,
        _         => TESTNET_SEEDS,
    }
}
