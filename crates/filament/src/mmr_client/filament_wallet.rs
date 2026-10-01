// src/mmr_client/filament_wallet.rs — Filament watch-only wallet
//
// Delegates UTXO discovery to a configured Keystone full-node.
// All returned data is independently verifiable against local MMR peaks.

use serde::{Deserialize, Serialize};

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
        let endpoints = self.keystone_endpoints.clone();
        if endpoints.is_empty() {
            return Ok(RefreshOutcome::default());
        }
        let addr = self.address.clone();
        let http = self.http.clone();

        let fetches = endpoints.into_iter().map(|ep| {
            let http = http.clone();
            let addr = addr.clone();
            async move {
                let utxo_url = format!("{}/explorer/utxos?address={}", ep, addr);
                let utxos = match http.get(&utxo_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        resp.json::<Vec<UtxoEntry>>().await.ok()
                    }
                    _ => None,
                };

                let hist_url = format!("{}/explorer/history?address={}&n=100", ep, addr);
                let history = match http.get(&hist_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        resp.json::<Vec<TxHistoryEntry>>().await.ok()
                    }
                    _ => None,
                };

                (ep, utxos, history)
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

    /// Select UTXOs for a given spend amount across all shards (FA-6).
    /// Returns UTXOs sufficient to cover `amount_atoms + fee_atoms`,
    /// preferring `preferred_shard` first, then falling back to other shards.
    pub fn select_utxos_for_amount(
        &self,
        amount_atoms: u64,
        fee_atoms: u64,
        preferred_shard: Option<u16>,
    ) -> Result<Vec<&UtxoEntry>, String> {
        let need = amount_atoms.checked_add(fee_atoms)
            .ok_or("Amount overflow")?;

        // Sort order: preferred shard first, then by value descending (coin selection)
        let mut sorted: Vec<&UtxoEntry> = self.utxos.iter()
            .filter(|u| u.confirmations >= 1)
            .collect();

        sorted.sort_by(|a, b| {
            let a_pref = preferred_shard.map_or(false, |s| a.shard_id == s);
            let b_pref = preferred_shard.map_or(false, |s| b.shard_id == s);
            b_pref.cmp(&a_pref)
                .then(b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal))
        });

        let mut selected: Vec<&UtxoEntry> = Vec::new();
        let mut total: u64 = 0;
        for utxo in sorted {
            selected.push(utxo);
            total += (utxo.value * ATOMS_PER_COIN) as u64;
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
    #[cfg(feature = "full-node")]
    pub async fn submit_transaction(&self, req: &SendRequest) -> Result<SendResponse, String> {
        if self.keystone_endpoints.is_empty() {
            return Err("No Keystone endpoint configured".to_string());
        }

        let mut last_err: Option<String> = None;
        for ep in &self.keystone_endpoints {
            let url = format!("{}/wallet/send", ep);
            match self.http.post(&url).json(req).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json::<SendResponse>().await.map_err(|e| e.to_string());
                }
                Ok(resp) => {
                    last_err = Some(format!("{} rejected (HTTP {})", ep, resp.status()));
                }
                Err(e) => {
                    last_err = Some(format!("{} unreachable: {}", ep, e));
                }
            }
        }

        // Every configured endpoint failed. Report it rather than invent an id:
        // a fabricated "txid" can never match what a node or the explorer
        // reports, so `watch_tx` would wait on it forever (VF-3).
        Err(format!(
            "no Keystone endpoint accepted the transaction ({})",
            last_err.unwrap_or_default(),
        ))
    }

    #[cfg(not(feature = "full-node"))]
    pub async fn submit_transaction(&self, req: &SendRequest) -> Result<SendResponse, String> {
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
            version: 2, // TX-11: every spend is version 2 (sighash v2)
            inputs,
            outputs,
            locktime: current_height,
            expiration_height: current_height.saturating_add(144),
            witnesses: Vec::new(),
        };

        // Sign with Schnorr: one key per input (all inputs belong to same wallet)
        let keys: Vec<SecretKey> = (0..tx.inputs.len()).map(|_| secret_key).collect();
        // chain_id = shard_id + 1. This used to pass `req.shard_id as u8`, so
        // every signature was for the wrong chain and failed TX-5 on a node.
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
