// src/mmr_client/ipp_api.rs
//
// Instant payment provider commands (IPP-MSG-1 wiring), shared by the local HTTP API
// (`filament_server.rs`, `/ipp/*`) and the desktop app's commands.
// They sit on `ipp_client::IppClient` and `escrow_api` / `wallet::escrow`; protocol and what the
// client checks are in `ipp_client.rs`.
//
// * Heights come from the light client's own verified chain state (`require_tip`), never from the
//   request or the provider: the provider's H is checked against it (`new_policy`, spec §5.1).
// * Signing uses the wallet's hot key (`FilamentWallet::with_signing_key`); the key never leaves
//   the wallet. A watch-only wallet gets a clear refusal, not a provider round trip.
// * The provider is identified by its endpoint and its public key (the registry record, until the
//   SAM registry lookup exists). The key comes from the caller; an answer signed by any other key
//   is refused.
// * The provider's word is not a chain fact. `funding` tells the provider about outputs this wallet
//   already recorded (indexer or Path-2 watch, both proof-checked or the user's own entry);
//   `pay` returns a commitment the caller still confirms on chain once the spend is in a block.

pub use network_common::common::ipp::{BroadcastNotif, Commitment};
use network_common::common::ipp::Outpoint;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::mmr_client::escrow_api::{
    self, EscrowApiError, EscrowView, PayRequest, DEFAULT_MIN_BLOCKS_LEFT, DEFAULT_MIN_LEAD_BLOCKS,
};
use crate::mmr_client::filament_wallet::FilamentWallet;
use crate::mmr_client::ipp_client::{IppClient, IppClientError};
use crate::mmr_client::multi_chain_client::MultiChainClient;
use crate::wallet::escrow::EscrowStore;

type Result<T> = std::result::Result<T, EscrowApiError>;

fn default_slots() -> u32 {
    1
}

/// A provider unreachable or answering with an error is "unavailable"; a message that does not
/// check out, or terms the wallet refuses, is the caller's problem to look at.
fn client_err(e: IppClientError) -> EscrowApiError {
    match e {
        IppClientError::Http(_) | IppClientError::Status { .. } => EscrowApiError::Unavailable(e.to_string()),
        _ => EscrowApiError::BadRequest(e.to_string()),
    }
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| EscrowApiError::BadRequest(format!("{what} must be 32 bytes of hex")))
}

/// https, or http to this machine (a local provider or the reference stub). Plain http to
/// anything else would send every session id and commitment in the clear.
pub fn check_provider_url(url: &str) -> Result<()> {
    let u = url.trim();
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"];
    let ok = u.starts_with("https://")
        || local.iter().any(|p| u.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')));
    if ok {
        Ok(())
    } else {
        Err(EscrowApiError::BadRequest("provider_url must be https:// (http:// only for 127.0.0.1, localhost or [::1])".into()))
    }
}

fn signing_key(wallet: &FilamentWallet) -> Result<SecretKey> {
    wallet.with_signing_key(|k| *k).map_err(EscrowApiError::BadRequest)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── Open ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct IppOpenRequest {
    pub provider_url: String,
    /// The provider's x-only key (64 hex): its registry record.
    pub provider_pk_hex: String,
    #[serde(default)]
    pub provider_label: String,
    /// `None` = beacon chain; `Some(n)` = shard n (0-indexed).
    #[serde(default)]
    pub shard_id: Option<u16>,
    pub amount_atoms: u64,
    #[serde(default = "default_slots")]
    pub slots: u32,
    /// Requested lock length N; the provider answers with the absolute H.
    pub lock_blocks: u32,
    #[serde(default)]
    pub min_lead_blocks: Option<u32>,
}

/// Open a balance with the provider and store the escrow (policy, provider endpoint, session).
/// The funding transaction is an ordinary send to `policy_hash_hex`; then call [`funding`].
pub async fn open(
    store: &EscrowStore,
    wallet: &FilamentWallet,
    client: &MultiChainClient,
    req: &IppOpenRequest,
) -> Result<EscrowView> {
    let tip = escrow_api::require_tip(client, req.shard_id).await?;
    open_at_tip(store, wallet, req, tip).await
}

/// [`open`] with the verified tip given.
pub async fn open_at_tip(store: &EscrowStore, wallet: &FilamentWallet, req: &IppOpenRequest, tip: u32) -> Result<EscrowView> {
    check_provider_url(&req.provider_url)?;
    if req.amount_atoms == 0 || req.slots == 0 || req.lock_blocks == 0 {
        return Err(EscrowApiError::BadRequest("amount, slots and lock_blocks must be non-zero".into()));
    }
    let provider_pk = hex32(&req.provider_pk_hex, "provider_pk_hex")?;
    let key = signing_key(wallet)?;
    let chain_id = req.shard_id.map_or(0, network_common::transaction::shard_chain_id);
    let lead = req.min_lead_blocks.unwrap_or(DEFAULT_MIN_LEAD_BLOCKS);
    let opened = IppClient::new(&req.provider_url, provider_pk)
        .open_balance(&key, chain_id, req.amount_atoms, req.slots, req.lock_blocks, tip, lead)
        .await
        .map_err(client_err)?;
    let rec = store.add(&opened.policy, req.shard_id, &req.provider_label)?;
    let rec = store.set_provider_session(&rec.id, req.provider_url.trim(), &opened.session_id)?;
    Ok(escrow_api::view(rec, Some(tip)))
}

// ─── Funding notice ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct IppFundingRequest {
    /// The funding transaction's id (64 hex).
    pub funding_txid_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IppFundingResponse {
    pub escrow_id: String,
    pub outpoints_reported: usize,
}

/// Tell the provider the funding is in a block: reports every funding output this wallet has
/// recorded for the escrow. The provider checks them through its own nodes.
pub async fn funding(wallet: &FilamentWallet, store: &EscrowStore, id: &str, req: &IppFundingRequest) -> Result<IppFundingResponse> {
    let rec = store.get(id)?;
    let (url, session) = provider_session(&rec)?;
    if rec.outpoints.is_empty() {
        return Err(EscrowApiError::BadRequest("no funding output is recorded for this escrow yet (wait for the watch or add it)".into()));
    }
    let txid = hex32(&req.funding_txid_hex, "funding_txid_hex")?;
    let outpoints: Vec<Outpoint> = rec.outpoints.iter().map(|o| Outpoint { height: o.height, output_idx: o.output_idx }).collect();
    let n = outpoints.len();
    let key = signing_key(wallet)?;
    IppClient::new(&url, hex32(&rec.provider_pk_hex, "stored provider key")?)
        .funding_notif(&key, &session, txid, outpoints)
        .await
        .map_err(client_err)?;
    Ok(IppFundingResponse { escrow_id: rec.id, outpoints_reported: n })
}

fn provider_session(rec: &crate::wallet::escrow::EscrowRecord) -> Result<(String, String)> {
    match (&rec.provider_url, &rec.session_id) {
        (Some(u), Some(s)) => Ok((u.clone(), s.clone())),
        _ => Err(EscrowApiError::BadRequest("this escrow was not opened through a provider (no endpoint or session stored)".into())),
    }
}

// ─── Pay ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct IppPayRequest {
    #[serde(flatten)]
    pub pay: PayRequest,
    /// The merchant's payment request id (opaque string).
    pub payment_request_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IppPayResponse {
    pub escrow_id: String,
    pub payment_request_id: String,
    /// Txid of the payment the provider will complete once the merchant confirms delivery.
    pub txid: String,
    pub commitment: Commitment,
}

/// Build the payment and sign the payer's half (as `escrow_api::pay`), hand it to the provider and
/// return the commitment, checked against what was sent.
pub async fn pay(
    store: &EscrowStore,
    wallet: &FilamentWallet,
    client: &MultiChainClient,
    id: &str,
    req: &IppPayRequest,
) -> Result<IppPayResponse> {
    let rec = store.get(id)?;
    let tip = escrow_api::require_tip(client, rec.shard_id).await?;
    pay_at_tip(store, wallet, id, req, tip).await
}

/// [`pay`] with the verified tip given.
pub async fn pay_at_tip(store: &EscrowStore, wallet: &FilamentWallet, id: &str, req: &IppPayRequest, tip: u32) -> Result<IppPayResponse> {
    let rec = store.get(id)?;
    let (url, session) = provider_session(&rec)?;
    if req.payment_request_id.trim().is_empty() {
        return Err(EscrowApiError::BadRequest("payment_request_id is required".into()));
    }
    let built = escrow_api::pay_at_tip(store, wallet, id, &req.pay, tip)?;
    let msg = built.to_message(&session, &req.payment_request_id, rec.chain_id());
    let policy = rec.policy()?;
    let key = signing_key(wallet)?;
    let margin = req.pay.min_blocks_left.unwrap_or(DEFAULT_MIN_BLOCKS_LEFT);
    let commitment = IppClient::new(&url, hex32(&rec.provider_pk_hex, "stored provider key")?)
        .pay_half_sign(&key, &msg, &policy, margin, now_unix())
        .await
        .map_err(client_err)?;
    Ok(IppPayResponse {
        escrow_id: rec.id,
        payment_request_id: req.payment_request_id.clone(),
        txid: built.txid,
        commitment,
    })
}

// ─── Delivery (merchant) ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct IppDeliveryRequest {
    pub provider_url: String,
    pub provider_pk_hex: String,
    pub payment_request_id: String,
}

/// Merchant side: confirm delivery. The provider completes the spend, broadcasts it and answers
/// with the txid; confirm the txid through your own nodes. Signed with this wallet's hot key, which
/// must be the payment's recipient.
pub async fn delivery_confirm(wallet: &FilamentWallet, req: &IppDeliveryRequest) -> Result<BroadcastNotif> {
    check_provider_url(&req.provider_url)?;
    let key = signing_key(wallet)?;
    IppClient::new(&req.provider_url, hex32(&req.provider_pk_hex, "provider_pk_hex")?)
        .delivery_confirm(&key, &req.payment_request_id, now_unix())
        .await
        .map_err(client_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_url_must_be_https_or_loopback() {
        for ok in ["https://provider.example", "https://provider.example:8443/ipp", "http://127.0.0.1:7700", "http://localhost", "http://[::1]:7700/x"] {
            assert!(check_provider_url(ok).is_ok(), "{ok}");
        }
        for bad in ["http://provider.example", "http://127.0.0.1.evil.example", "http://localhost.evil.example", "ftp://x", "provider.example", ""] {
            assert!(check_provider_url(bad).is_err(), "{bad}");
        }
    }
}
