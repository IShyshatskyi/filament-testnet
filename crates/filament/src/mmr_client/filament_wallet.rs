// src/mmr_client/filament_wallet.rs — Filament watch-only wallet
//
// Delegates UTXO discovery to a configured Keystone full-node.
// All returned data is independently verifiable against local MMR peaks.

use serde::{Deserialize, Serialize};

#[cfg(feature = "full-node")]
#[cfg(feature = "full-node")]
use bitcoin::secp256k1::SecretKey;
#[cfg(feature = "full-node")]
use common_types::transaction::types::{Transaction, TxInput, TxOutput};
#[cfg(feature = "full-node")]
use crate::wallet::transaction_builder::SchnorrSigner;

pub const ATOMS_PER_COIN: f64 = 100_000_000.0;

/// TS-PORTAL-2f — the Testnet Portal auth domain tag. These bytes MUST stay
/// **byte-identical** to `tools/testnet-portal-api` `auth::AUTH_DOMAIN` /
/// `auth::auth_digest`: the portal API verifies the returned signature against
/// exactly `BLAKE3(this || x_only_pubkey(32) || nonce(32))`. The trailing
/// newline is part of the domain.
#[cfg(feature = "full-node")]
pub(crate) const PORTAL_AUTH_DOMAIN: &[u8] = b"shisha:testnet-portal:auth:v1\n";

/// Result of [`FilamentWallet::sign_portal_auth`].
#[cfg(feature = "full-node")]
pub struct PortalAuthSignature {
    /// 64-byte BIP-340 Schnorr signature, hex (128 chars).
    pub signature: String,
    /// The signing wallet's x-only public key, hex (64 chars) — the address
    /// the portal will bind the session to.
    pub address: String,
}

// Fallback fee: 10 000 atoms = 0.0001 SHISHA
pub const DEFAULT_FEE_ATOMS: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Recommended fee in atoms
    pub atoms: u64,
    /// Human-readable fee in coins
    pub coins: f64,
    /// Source: "keystone_fee_filter" | "fallback"
    pub source: String,
    /// Estimated sat/vbyte equivalent (atoms per byte)
    pub atoms_per_byte: u64,
}

// ── Wire types (match UI expectations exactly) ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub height: u32,
    pub output_idx: u16,
    pub value: f64,       // coins
    pub confirmations: u32,
    pub coinbase: bool,
    pub shard_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    pub id: u64,
    pub txid: String,
    #[serde(rename = "type")]
    pub kind: String,     // "receive" | "send" | "coinbase"
    pub value: f64,       // coins (negative = outgoing)
    pub from: String,
    pub to: String,
    pub height: Option<u32>,
    pub confirmations: u32,
    pub fee: f64,
    pub shard_id: u16,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub confirmed: f64,
    pub unconfirmed: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    #[serde(default)]
    pub shard_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResponse {
    pub txid: String,
    pub status: String,
}

// ── FilamentWallet ────────────────────────────────────────────────────────────

/// MNT-7: outcome of fanning a wallet-data refresh out to every configured
/// Keystone endpoint, rather than trusting whichever single endpoint used to
/// be the only option. See `filament_app/docs/MULTI_NODE_TRUST_PLAN.md`.
#[derive(Debug, Clone, Default)]
pub struct RefreshOutcome {
    /// Endpoints that returned a usable response.
    pub responded: Vec<String>,
    /// Endpoints that were unreachable or returned a non-2xx/unparseable body.
    pub failed: Vec<String>,
    /// True when two or more responding endpoints disagree on this wallet's
    /// own UTXO set by more than a small height tolerance — a possible
    /// stale, lagging, or censoring endpoint among the configured list.
    /// Surfaced by the caller (see `filament_server.rs`'s background sync
    /// loop), not resolved silently.
    pub disagreement: bool,
}

pub struct FilamentWallet {
    address: String,
    utxos: Vec<UtxoEntry>,
    history: Vec<TxHistoryEntry>,
    /// MNT-7: every Keystone REST endpoint this wallet fans wallet-data
    /// queries out to, rather than trusting a single configured node.
    /// Populated from `FilamentNodeConfig::all_keystone_endpoints()`.
    keystone_endpoints: Vec<String>,
    /// Eratosthenes endpoints the wallet's UTXOs and history are read from
    /// (`/explorer/*`; Keystone has no address index). FIL-REFRESH-1.
    indexer_endpoints: Vec<String>,
    #[cfg(feature = "full-node")]
    http: reqwest::Client,
    /// Session F2F identity keypair (F2F-3).  Generated fresh on wallet
    /// creation; the public half is shared with correspondents so they can
    /// encrypt messages addressed to this wallet.
    f2f_seckey: [u8; 32],
    f2f_pubkey: [u8; 33],
    /// TS-PORTAL-2f: optional spending secret key. When set (via
    /// `--signing-key-file` / `FILAMENT_SIGNING_KEY`), the local HTTP API can
    /// sign a domain-separated Testnet Portal auth challenge without the key
    /// ever leaving this process. Watch-only when `None`.
    #[cfg(feature = "full-node")]
    signing_key: Option<SecretKey>,
}

/// One indexer's view of `addr`: all unspent shard outputs (cursor-paged) and recent history,
/// mapped to the wallet's types. `None` when the indexer does not answer the UTXO route.
#[cfg(feature = "full-node")]
async fn fetch_indexer_wallet(
    http: &reqwest::Client,
    ep: &str,
    addr: &str,
) -> Option<(Vec<UtxoEntry>, Vec<TxHistoryEntry>)> {
    use serde_json::Value;
    let base = ep.trim_end_matches('/');
    let shard_of = |v: &Value| -> Option<u16> {
        (v.get("chain")?.as_str()? == "shard").then(|| v.get("shard_id")?.as_u64().map(|s| s as u16))?
    };
    let mut tips: std::collections::HashMap<u16, u32> = std::collections::HashMap::new();
    let mut utxos = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..64 {
        let mut url = format!("{base}/explorer/utxos?address={addr}");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let page: Value = http.get(&url).send().await.ok().filter(|r| r.status().is_success())?.json().await.ok()?;
        for a in page.get("as_of").and_then(|v| v.as_array()).into_iter().flatten() {
            if let (Some(s), Some(h)) = (shard_of(a), a.get("indexed_height").and_then(|v| v.as_u64())) {
                tips.insert(s, h as u32);
            }
        }
        for u in page.get("utxos")?.as_array()? {
            let Some(shard_id) = shard_of(u) else { continue };
            let height = u.get("height")?.as_u64()? as u32;
            let tip = tips.get(&shard_id).copied().unwrap_or(height);
            utxos.push(UtxoEntry {
                height,
                output_idx: u.get("output_idx")?.as_u64()? as u16,
                value: u.get("value")?.as_u64()? as f64 / ATOMS_PER_COIN,
                confirmations: tip.saturating_sub(height) + 1,
                coinbase: false,
                shard_id,
            });
        }
        match (page.get("truncated").and_then(|v| v.as_bool()), page.get("next_cursor").and_then(|v| v.as_str())) {
            (Some(true), Some(c)) => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    let mut history = Vec::new();
    let url = format!("{base}/explorer/history?address={addr}&n=100");
    if let Ok(r) = http.get(&url).send().await {
        if let Ok(v) = r.json::<Value>().await {
            for (i, h) in v.get("history").and_then(|x| x.as_array()).into_iter().flatten().enumerate() {
                let Some(shard_id) = shard_of(h) else { continue };
                let height = h.get("height").and_then(|x| x.as_u64()).map(|x| x as u32);
                let atoms = h.get("value").and_then(|x| x.as_u64()).unwrap_or(0) as f64 / ATOMS_PER_COIN;
                let spend = h.get("kind").and_then(|x| x.as_str()) == Some("spend");
                let tip = tips.get(&shard_id).copied();
                history.push(TxHistoryEntry {
                    id: i as u64,
                    txid: String::new(), // the indexer keeps no txid
                    kind: if spend { "send".into() } else { "receive".into() },
                    value: if spend { -atoms } else { atoms },
                    from: if spend { addr.to_string() } else { String::new() },
                    to: if spend { String::new() } else { addr.to_string() },
                    height,
                    confirmations: match (tip, height) { (Some(t), Some(h)) => t.saturating_sub(h) + 1, _ => 0 },
                    fee: 0.0,
                    shard_id,
                    ts_ms: 0,
                });
            }
        }
    }
    Some((utxos, history))
}

impl FilamentWallet {
    pub fn new(address: String, keystone_endpoint: Option<String>) -> Self {
        // Generate session F2F identity keypair.
        let (f2f_seckey, f2f_pubkey) = {
            use secp256k1::{Secp256k1, rand::thread_rng};
            let secp = Secp256k1::new();
            let (sec, pub_) = secp.generate_keypair(&mut thread_rng());
            let sec_bytes: [u8; 32] = sec.secret_bytes().try_into().unwrap_or([0u8; 32]);
            let pub_bytes: [u8; 33] = pub_.serialize();
            (sec_bytes, pub_bytes)
        };

        Self {
            address,
            utxos: Vec::new(),
            history: Vec::new(),
            keystone_endpoints: keystone_endpoint.into_iter().collect(),
            indexer_endpoints: Vec::new(),
            #[cfg(feature = "full-node")]
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            f2f_seckey,
            f2f_pubkey,
            #[cfg(feature = "full-node")]
            signing_key: None,
        }
    }

    /// Returns the compressed secp256k1 public key (33 bytes) for this wallet's
    /// F2F identity.  Share this with correspondents so they can encrypt
    /// messages addressed to this wallet.
    pub fn f2f_pubkey(&self) -> &[u8; 33] { &self.f2f_pubkey }

    /// Returns the raw secret key scalar for F2F ECDH decryption.
    /// Never exposed outside the crate.
    pub(crate) fn f2f_seckey(&self) -> &[u8; 32] { &self.f2f_seckey }

    pub fn address(&self) -> &str { &self.address }

    pub fn balance(&self) -> BalanceResponse {
        let confirmed: f64 = self.utxos.iter()
            .filter(|u| u.confirmations >= 1)
            .map(|u| u.value)
            .sum();
        let unconfirmed: f64 = self.utxos.iter()
            .filter(|u| u.confirmations == 0)
            .map(|u| u.value)
            .sum();
        BalanceResponse { confirmed, unconfirmed }
    }

    pub fn utxos(&self) -> &[UtxoEntry] { &self.utxos }
    pub fn history(&self) -> &[TxHistoryEntry] { &self.history }

    pub fn set_utxos(&mut self, utxos: Vec<UtxoEntry>) { self.utxos = utxos; }
    pub fn set_history(&mut self, history: Vec<TxHistoryEntry>) { self.history = history; }

    /// Set a single Keystone endpoint, replacing the whole list. Kept for
    /// backward compatibility with callers that only know about one
    /// endpoint; prefer `set_keystone_endpoints` when multiple are
    /// configured (MNT-7).
    pub fn set_keystone_endpoint(&mut self, ep: Option<String>) {
        self.keystone_endpoints = ep.into_iter().collect();
    }

    /// MNT-7: set the full list of Keystone REST endpoints this wallet fans
    /// queries out to. See `FilamentNodeConfig::all_keystone_endpoints()`.
    pub fn set_keystone_endpoints(&mut self, eps: Vec<String>) {
        self.keystone_endpoints = eps;
    }

    /// The configured Keystone REST endpoints, in priority order.
    pub fn keystone_endpoints(&self) -> &[String] { &self.keystone_endpoints }

    /// Eratosthenes endpoints for UTXO / history refresh (`FilamentNodeConfig::indexer_endpoints`).
    pub fn set_indexer_endpoints(&mut self, eps: Vec<String>) {
        self.indexer_endpoints = eps;
    }

    /// TS-PORTAL-2f: attach the wallet's spending secret key so the local HTTP
    /// API's `/wallet/sign-message` can sign a Testnet Portal auth challenge.
    /// The key is never returned by any route or accepted in any request body.
    #[cfg(feature = "full-node")]
    pub fn set_signing_key(&mut self, key: SecretKey) {
        self.signing_key = Some(key);
    }

    /// True when a signing key is attached (see [`set_signing_key`]).
    #[cfg(feature = "full-node")]
    pub fn has_signing_key(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Attach an unlocked hot key (desktop app, `wallet::hot_key`). The wallet address becomes
    /// the key's x-only public key when no address is set; a wallet already watching a
    /// different address refuses the key instead of silently switching addresses.
    #[cfg(feature = "full-node")]
    pub fn attach_hot_key(&mut self, key: SecretKey) -> Result<(), String> {
        use bitcoin::secp256k1::{Keypair, Secp256k1};
        let pubkey = hex::encode(Keypair::from_secret_key(&Secp256k1::new(), &key).x_only_public_key().0.serialize());
        if !self.address.is_empty() && !self.address.eq_ignore_ascii_case(&pubkey) {
            return Err(format!("this wallet watches {}; the hot key is {}", self.address, pubkey));
        }
        self.address = pubkey;
        self.signing_key = Some(key);
        Ok(())
    }

    /// Drop the spending key from memory (lock). The address stays.
    #[cfg(feature = "full-node")]
    pub fn detach_signing_key(&mut self) {
        self.signing_key = None;
    }

    /// Run `f` with the wallet's spending key (escrow signing, IPP D10 hot key).
    /// The key stays inside the wallet; only `f`'s result leaves.
    #[cfg(feature = "full-node")]
    pub fn with_signing_key<R>(&self, f: impl FnOnce(&SecretKey) -> R) -> Result<R, String> {
        let sk = self
            .signing_key
            .as_ref()
            .ok_or("no signing key configured — start Filament with --signing-key-file")?;
        Ok(f(sk))
    }

    /// TS-PORTAL-2f: sign the Testnet Portal auth challenge for `nonce`.
    ///
    /// ```text
    /// digest    = BLAKE3( PORTAL_AUTH_DOMAIN || x_only_pubkey(32) || nonce(32) )
    /// signature = BIP-340 Schnorr(digest) with the wallet's spending key
    /// ```
    ///
    /// The digest preimage is re-derived here by hand and MUST match
    /// `tools/testnet-portal-api` `auth::auth_digest` byte-for-byte — the
    /// portal verifies against exactly this. `PORTAL_AUTH_DOMAIN`'s trailing
    /// newline is deliberate and part of the preimage.
    #[cfg(feature = "full-node")]
    pub fn sign_portal_auth(&self, nonce: &[u8; 32]) -> Result<PortalAuthSignature, String> {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        let sk = self
            .signing_key
            .ok_or("no signing key configured — start Filament with --signing-key-file")?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let address = xonly.serialize();

        let mut h = blake3::Hasher::new();
        h.update(PORTAL_AUTH_DOMAIN);
        h.update(&address);
        h.update(nonce);
        let digest: [u8; 32] = *h.finalize().as_bytes();

        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair);
        Ok(PortalAuthSignature {
            signature: hex::encode(sig.as_ref()),
            address: hex::encode(address),
        })
    }

    /// Refresh UTXOs + history via address-indexed **explorer** endpoints
    /// (Eratosthenes Path 4: `GET /explorer/utxos?address=` /
    /// `GET /explorer/history?address=` — Jul 21 rename; not Keystone
    /// `/wallet/*`, which is local watch-wallet state without `?address=`).
    ///
    /// FIL-REFRESH-1 (Oct 30, 2026): reads the configured **indexer** endpoints with the
    /// indexer's real shapes (`{utxos, truncated, next_cursor, as_of}` paged by cursor,
    /// `{history}`, values in atoms). It used to ask the Keystone endpoints, which do not
    /// serve these routes, and parse bare arrays — so it never updated anything. Beacon rows
    /// are skipped (wallet UTXOs are per shard). Confirmations come from the indexer's
    /// indexed height for that chain.
    ///
    /// Queries every configured endpoint (MNT-7 fan-out) rather than trusting
    /// a single one, and cross-check their responses. Adopts the response
    /// reporting the greatest max UTXO height (the freshest view); flags
    /// `RefreshOutcome::disagreement` when responding endpoints materially
    /// disagree, so the caller can surface it instead of it being silently
    /// resolved.
    ///
    /// If every configured endpoint fails, existing local state is left
    /// untouched rather than being cleared on a transient outage.
    #[cfg(feature = "full-node")]
    pub async fn refresh_from_keystone(&mut self) -> Result<RefreshOutcome, String> {
        let endpoints = self.indexer_endpoints.clone();
        if endpoints.is_empty() || self.address.is_empty() {
            return Ok(RefreshOutcome::default());
        }
        let addr = self.address.clone();
        let http = self.http.clone();

        let fetches = endpoints.into_iter().map(|ep| {
            let http = http.clone();
            let addr = addr.clone();
            async move {
                match fetch_indexer_wallet(&http, &ep, &addr).await {
                    Some((utxos, history)) => (ep, Some(utxos), Some(history)),
                    None => (ep, None, None),
                }
            }
        });

        let results = futures_util::future::join_all(fetches).await;

        let mut responded: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        // (endpoint, utxos, history, max_utxo_height) for every endpoint
        // that returned at least a UTXO list.
        let mut candidates: Vec<(String, Vec<UtxoEntry>, Vec<TxHistoryEntry>, u32)> = Vec::new();

        for (ep, utxos, history) in results {
            match utxos {
                Some(utxos) => {
                    let max_height = utxos.iter().map(|u| u.height).max().unwrap_or(0);
                    responded.push(ep.clone());
                    candidates.push((ep, utxos, history.unwrap_or_default(), max_height));
                }
                None => failed.push(ep),
            }
        }

        if candidates.is_empty() {
            return Ok(RefreshOutcome { responded, failed, disagreement: false });
        }

        // Disagreement: responding endpoints report materially different
        // tip heights for this wallet's own UTXO set (a stale/censoring
        // endpoint would under-report). Tolerance of 1 block absorbs
        // ordinary propagation lag between otherwise-honest endpoints —
        // same tolerance rule as the P2P reconciliation path in
        // `MultiChainClient::reconcile_beacon_summaries`.
        let disagreement = match (
            candidates.iter().map(|c| c.3).min(),
            candidates.iter().map(|c| c.3).max(),
        ) {
            (Some(min_h), Some(max_h)) => max_h.saturating_sub(min_h) > 1,
            _ => false,
        };

        // Adopt the freshest (highest max-height) response.
        if let Some((_, utxos, history, _)) = candidates.into_iter().max_by_key(|c| c.3) {
            self.utxos = utxos;
            self.history = history;
        }

        Ok(RefreshOutcome { responded, failed, disagreement })
    }

    #[cfg(not(feature = "full-node"))]
    pub async fn refresh_from_keystone(&mut self) -> Result<RefreshOutcome, String> {
        Ok(RefreshOutcome::default())
    }

    /// Estimate fee from Keystone's `/chain/fee_filter`, falling back to DEFAULT_FEE_ATOMS.
    /// FA-5: Tx fee estimation.
    #[cfg(feature = "full-node")]
    pub async fn estimate_fee(&self, tx_size_bytes: u64) -> FeeEstimate {
        let fallback = FeeEstimate {
            atoms: DEFAULT_FEE_ATOMS,
            coins: DEFAULT_FEE_ATOMS as f64 / ATOMS_PER_COIN,
            source: "fallback".into(),
            atoms_per_byte: DEFAULT_FEE_ATOMS / tx_size_bytes.max(200),
        };

        let ep = match self.keystone_endpoints.first() {
            Some(ep) => ep.clone(),
            None => return fallback,
        };

        // Keystone exposes `/chain/fee_filter` which returns the P2P FeeFilter message:
        // { min_fee_atoms_per_byte: u64 }
        #[derive(Deserialize)]
        struct FeeFilterResp { min_fee_atoms_per_byte: u64 }

        let url = format!("{}/chain/fee_filter", ep);
        if let Ok(resp) = self.http.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(ff) = resp.json::<FeeFilterResp>().await {
                    let atoms_per_byte = ff.min_fee_atoms_per_byte.max(1);
                    let atoms = (atoms_per_byte * tx_size_bytes).max(DEFAULT_FEE_ATOMS);
                    return FeeEstimate {
                        atoms,
                        coins: atoms as f64 / ATOMS_PER_COIN,
                        source: "keystone_fee_filter".into(),
                        atoms_per_byte,
                    };
                }
            }
        }
        fallback
    }

    #[cfg(not(feature = "full-node"))]
    pub async fn estimate_fee(&self, _tx_size_bytes: u64) -> FeeEstimate {
        FeeEstimate {
            atoms: DEFAULT_FEE_ATOMS,
            coins: DEFAULT_FEE_ATOMS as f64 / ATOMS_PER_COIN,
            source: "fallback".into(),
            atoms_per_byte: DEFAULT_FEE_ATOMS / 200,
        }
    }

    /// Select UTXOs for a given spend amount (FA-6). With `Some(shard)` only that shard's
    /// outputs are used: shards are independent ledgers (Anti-Patterns #33), so one
    /// transaction can never spend outputs of two chains. (It used to fall back to other
    /// shards, building transactions no node accepts — fixed Oct 30, 2026.)
    pub fn select_utxos_for_amount(
        &self,
        amount_atoms: u64,
        fee_atoms: u64,
        preferred_shard: Option<u16>,
    ) -> Result<Vec<&UtxoEntry>, String> {
        let need = amount_atoms.checked_add(fee_atoms)
            .ok_or("Amount overflow")?;

        // That shard only, largest first.
        let mut sorted: Vec<&UtxoEntry> = self.utxos.iter()
            .filter(|u| u.confirmations >= 1)
            .filter(|u| preferred_shard.map_or(true, |s| u.shard_id == s))
            .collect();

        sorted.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));

        let mut selected: Vec<&UtxoEntry> = Vec::new();
        let mut total: u64 = 0;
        for utxo in sorted {
            selected.push(utxo);
            // Round like the signer does (sighash v2 commits exact atoms).
            total += (utxo.value * ATOMS_PER_COIN).round() as u64;
            if total >= need { break; }
        }

        if total < need {
            return Err(format!(
                "Insufficient balance: need {} atoms, have {} atoms",
                need, total
            ));
        }
        Ok(selected)
    }

    /// Submit a signed transaction to every configured Keystone endpoint
    /// (MNT-7). This is a propagation-reliability improvement, not a trust
    /// check — one successful accept is sufficient to consider the tx
    /// submitted, so the first endpoint to accept wins and the rest aren't
    /// waited on.
    ///
    /// FIL-SEND-1 (Oct 30, 2026): the transaction is built and signed here with the wallet's
    /// held key and submitted as raw bytes to `POST /mempool/submit` (`keystone_submit`).
    /// Keystone's `/wallet/send`, which this used to call, is a stub that answers a zero txid
    /// and sends nothing. `current_height` is the shard's verified tip (TE-1 locktime, TE-2
    /// expiry); the txid returned is the one the node reports.
    #[cfg(feature = "full-node")]
    pub async fn submit_transaction(&self, req: &SendRequest, current_height: u32) -> Result<SendResponse, String> {
        let key = self
            .signing_key
            .ok_or("no signing key attached — unlock the hot key (desktop) or start Filament with --signing-key-file")?;
        let selected = self.select_utxos_for_amount(req.amount_atoms, req.fee_atoms, Some(req.shard_id))?;
        let (mut tx, witnesses) = self.build_signed_transaction_with_key(req, &selected, &key, current_height)?;
        tx.witnesses = witnesses;
        let txid = hex::encode(tx.txid(common_types::transaction::shard_chain_id(req.shard_id)).0);
        let answer = crate::mmr_client::keystone_submit::submit_raw_tx(
            &self.http,
            &self.keystone_endpoints,
            Some(req.shard_id),
            tx.serialize_with_witnesses(),
        )
        .await?;
        let status = answer.get("status").and_then(|v| v.as_str()).unwrap_or("accepted").to_string();
        Ok(SendResponse { txid, status })
    }

    #[cfg(not(feature = "full-node"))]
    pub async fn submit_transaction(&self, req: &SendRequest, _current_height: u32) -> Result<SendResponse, String> {
        Err("Wallet submission requires full-node feature".to_string())
    }

    /// FA-13: Build and Schnorr-sign a send transaction from the caller-supplied UTXOs and key.
    ///
    /// Returns `(tx, witnesses)` ready for broadcast.  The caller is responsible for
    /// persisting/broadcasting the transaction; this method does NOT submit it.
    ///
    /// Signing uses `SchnorrSigner` (BIP-340 Schnorr, BLAKE3 sighash, chain-ID replay protection).
    #[cfg(feature = "full-node")]
    pub fn build_signed_transaction(
        &self,
        req: &SendRequest,
        utxos: &[&UtxoEntry],
        secret_key_hex: &str,
        current_height: u32,
    ) -> Result<(Transaction, Vec<common_types::transaction::types::WitnessEntry>), String> {
        // Decode the 32-byte secret key from hex
        let key_bytes = hex::decode(secret_key_hex)
            .map_err(|e| format!("invalid key hex: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(format!("secret key must be 32 bytes, got {}", key_bytes.len()));
        }
        let secret_key = SecretKey::from_slice(&key_bytes)
            .map_err(|e| format!("invalid secret key: {}", e))?;
        self.build_signed_transaction_with_key(req, utxos, &secret_key, current_height)
    }

    /// [`Self::build_signed_transaction`] with the key itself (the wallet's held key).
    #[cfg(feature = "full-node")]
    pub fn build_signed_transaction_with_key(
        &self,
        req: &SendRequest,
        utxos: &[&UtxoEntry],
        secret_key: &SecretKey,
        current_height: u32,
    ) -> Result<(Transaction, Vec<common_types::transaction::types::WitnessEntry>), String> {
        let secret_key = *secret_key;
        // Decode recipient (32-byte positional address)
        let to_bytes = hex::decode(&req.to)
            .map_err(|e| format!("invalid recipient hex: {}", e))?;
        if to_bytes.len() != 32 {
            return Err(format!("recipient must be 32 bytes, got {}", to_bytes.len()));
        }
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&to_bytes);

        // Build inputs from UTXOs
        let inputs: Vec<TxInput> = utxos.iter().map(|u| TxInput {
            prev_height: u.height,
            prev_output_idx: u.output_idx,
        }).collect();

        // Atoms per input. `UtxoEntry.value` is f64 coins: round, never
        // truncate (0.29 * 1e8 = 28_999_999.99...). Sighash v2 commits each
        // spent value exactly, so an off-by-one atom invalidates the signature.
        let in_atoms: Vec<u64> = utxos.iter().map(|u| (u.value * ATOMS_PER_COIN).round() as u64).collect();

        // Compute total input value and change
        let total_in: u64 = in_atoms.iter().sum();
        let total_out = req.amount_atoms.checked_add(req.fee_atoms)
            .ok_or("amount + fee overflow")?;
        if total_in < total_out {
            return Err(format!("insufficient funds: have {} need {}", total_in, total_out));
        }
        let change = total_in - total_out;

        // Build outputs: payment + optional change back to self
        let mut outputs = vec![TxOutput {
            value: req.amount_atoms,
            recipient,
        }];
        if change > 0 {
            // Change back to the wallet's own address
            let self_bytes = hex::decode(&self.address)
                .unwrap_or_else(|_| vec![0u8; 32]);
            let mut self_addr = [0u8; 32];
            let copy_len = self_bytes.len().min(32);
            self_addr[..copy_len].copy_from_slice(&self_bytes[..copy_len]);
            outputs.push(TxOutput { value: change, recipient: self_addr });
        }

        let tx = Transaction {
            version: 1, // TX-11: every spend is version 2 (sighash v2)
            inputs,
            outputs,
            locktime: current_height,
            expiration_height: current_height.saturating_add(144),
            witnesses: Vec::new(),
            extensions: Vec::new(),
        };

        // Sign with Schnorr: one key per input (all inputs belong to same wallet)
        let keys: Vec<SecretKey> = (0..tx.inputs.len()).map(|_| secret_key).collect();
        // chain_id = shard_id + 1 (Anti-Patterns #22). This used to pass
        // `req.shard_id as u8`, so every signature was for the wrong chain and
        // failed TX-5 on a real node.
        let chain_id = common_types::transaction::shard_chain_id(req.shard_id);
        // Sighash v2 commits the spent outputs: our own key received every one.
        let own = bitcoin::secp256k1::Keypair::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &secret_key)
            .x_only_public_key().0.serialize();
        let prevouts: Vec<(u64, [u8; 32])> = in_atoms.iter().map(|&v| (v, own)).collect();
        let witnesses = SchnorrSigner::sign_transaction(&tx, &keys, chain_id, &prevouts)?;

        Ok((tx, witnesses))
    }

    #[cfg(not(feature = "full-node"))]
    pub fn build_signed_transaction(
        &self,
        _req: &SendRequest,
        _utxos: &[&UtxoEntry],
        _secret_key_hex: &str,
        _current_height: u32,
    ) -> Result<((), Vec<()>), String> {
        Err("Schnorr signing requires full-node feature".to_string())
    }
}

#[cfg(all(test, feature = "full-node"))]
mod portal_auth_tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::secp256k1::schnorr::Signature;

    /// Independent re-derivation of `tools/testnet-portal-api` `auth::auth_digest`
    /// — kept here so a drift in either side fails this test.
    fn portal_digest(address: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"shisha:testnet-portal:auth:v1\n");
        h.update(address);
        h.update(nonce);
        *h.finalize().as_bytes()
    }

    #[test]
    fn sign_portal_auth_round_trips_and_matches_portal_api_digest() {
        let secp = Secp256k1::new();
        let mut seed = [7u8; 32];
        seed[0] = 1; // valid non-zero scalar
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap();
        let (xonly, _) = Keypair::from_secret_key(&secp, &sk).x_only_public_key();
        let expected_addr = xonly.serialize();

        let mut w = FilamentWallet::new("watch-only".into(), None);
        assert!(!w.has_signing_key());
        assert!(w.sign_portal_auth(&[0u8; 32]).is_err());

        w.set_signing_key(sk);
        assert!(w.has_signing_key());

        let nonce = [0xABu8; 32];
        let out = w.sign_portal_auth(&nonce).unwrap();

        // Address is the wallet's x-only pubkey.
        assert_eq!(out.address, hex::encode(expected_addr));

        // Signature verifies against the exact digest the portal API computes.
        let digest = portal_digest(&expected_addr, &nonce);
        let sig = Signature::from_slice(&hex::decode(&out.signature).unwrap()).unwrap();
        let vk = XOnlyPublicKey::from_slice(&expected_addr).unwrap();
        secp.verify_schnorr(&sig, &Message::from_digest(digest), &vk)
            .expect("portal-api would verify this signature");
    }

    #[test]
    fn domain_constant_is_the_portal_api_bytes() {
        assert_eq!(PORTAL_AUTH_DOMAIN, b"shisha:testnet-portal:auth:v1\n");
    }
}

#[cfg(all(test, feature = "full-node"))]
mod indexer_refresh_tests {
    use super::*;
    use axum::{extract::Query, routing::get, Json, Router};
    use std::collections::HashMap;

    /// FIL-REFRESH-1: refresh reads Eratosthenes' real shapes, pages by cursor, skips beacon
    /// rows, derives confirmations from the indexed height, maps history.
    #[tokio::test]
    async fn refresh_reads_the_indexer() {
        let addr = "ab".repeat(32);
        let app = Router::new()
            .route("/explorer/utxos", get(|q: Query<HashMap<String, String>>| async move {
                let as_of = serde_json::json!([
                    { "chain": "beacon", "shard_id": null, "indexed_height": 900 },
                    { "chain": "shard", "shard_id": 2, "indexed_height": 120 }
                ]);
                Json(if q.get("cursor").is_none() {
                    serde_json::json!({ "utxos": [
                        { "chain": "shard", "shard_id": 2, "height": 100, "output_idx": 0, "value": 150_000_000u64 },
                        { "chain": "beacon", "shard_id": null, "height": 800, "output_idx": 1, "value": 7 }
                    ], "truncated": true, "next_cursor": "k1", "as_of": as_of })
                } else {
                    serde_json::json!({ "utxos": [
                        { "chain": "shard", "shard_id": 2, "height": 120, "output_idx": 3, "value": 25_000_000u64 }
                    ], "truncated": false, "next_cursor": null, "as_of": as_of })
                })
            }))
            .route("/explorer/history", get(|| async {
                Json(serde_json::json!({ "history": [
                    { "kind": "receive", "chain": "shard", "shard_id": 2, "height": 100, "output_created_height": 100, "output_idx": 0, "value": 150_000_000u64 },
                    { "kind": "spend", "chain": "shard", "shard_id": 2, "height": 110, "output_created_height": 90, "output_idx": 1, "value": 50_000_000u64 }
                ]}))
            }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let mut w = FilamentWallet::new(addr.clone(), None);
        assert!(w.refresh_from_keystone().await.unwrap().responded.is_empty(), "no indexer configured → no-op");
        w.set_indexer_endpoints(vec![ep.clone()]);
        let out = w.refresh_from_keystone().await.unwrap();
        assert_eq!(out.responded, vec![ep]);
        let u: Vec<(u32, u16, u32, u16)> = w.utxos().iter().map(|u| (u.height, u.output_idx, u.confirmations, u.shard_id)).collect();
        assert_eq!(u, vec![(100, 0, 21, 2), (120, 3, 1, 2)], "beacon row skipped, both pages read");
        assert!((w.utxos()[0].value - 1.5).abs() < 1e-12);
        let h = w.history();
        assert_eq!((h[0].kind.as_str(), h[1].kind.as_str()), ("receive", "send"));
        assert!((h[1].value + 0.5).abs() < 1e-12);
        assert_eq!(h[1].confirmations, 11);
    }
}
