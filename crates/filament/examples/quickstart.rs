// Filament quickstart — the "Drop it into your Rust project" snippet on the website's
// Filament page (website `pages/Filament.html`) is a copy of this file; `cargo test -p filament`
// compiles it, so an API change breaks the build here instead of silently staling the page
// (website `scripts/check_filament_snippets.sh` compares the two).
//
// Run against a Keystone's light-client summary API (port 8080 by default):
//   cargo run -p filament --example quickstart -- light_client_config.toml http://127.0.0.1:8080
use filament::{InMemoryStorage, MultiChainClient};
use filament::mmr_client::multi_chain_client::PeerChainSummaryResponse;
use common_types::common::proofs::MMRChainSummary;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let config = args.next().unwrap_or_else(|| "light_client_config.toml".into());
    let keystone = args.next().unwrap_or_else(|| "http://127.0.0.1:8080".into());

    // Genesis anchors come from the bootstrap config, never from the peer.
    let storage = Box::new(InMemoryStorage::new());
    let mut client = MultiChainClient::from_config_file(&config, storage)?;
    client.init_from_network("devnet").await?;

    // Fetch the peer's chain summary and verify it (weighted MMR proof against the anchor).
    let summary: MMRChainSummary = reqwest::get(format!("{keystone}/chain/summary"))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let outcome = client
        .reconcile_beacon_summaries(vec![PeerChainSummaryResponse { peer_id: keystone, summary }])
        .await?;

    let tip = client.get_beacon_state().await?.tip.height();
    println!("verified beacon tip #{tip} (applied: {}, rejected: {:?})", outcome.applied, outcome.rejected_peers);
    Ok(())
}
