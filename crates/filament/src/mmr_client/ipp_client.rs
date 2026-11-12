// src/mmr_client/ipp_client.rs
//
// HTTPS client for an instant payment provider endpoint. Wire types and the signed
// envelope: `network_common::ipp`.
//
// * Every request is a `SignedMessage` POSTed to `{base}/ipp/v1/{type}`; the answer is a
//   `SignedMessage` too. Both directions are verified here, and the answer must be signed by
//   the provider key the caller passed in (the registry record). A message never introduces
//   its own trusted key (§2), so there is no "trust whoever answers" mode.
// * What a provider says about the chain is not a fact: the caller still checks the escrow
//   output, payment inclusion and depth through its own nodes (§1). This client checks only
//   what it can without chain state: signer, message type and version, the policy and
//   its hash, and that a commitment is about the payment that was sent.
// * The payer's key is passed per call and never stored; the wallet hands it out through
//   `FilamentWallet::with_signing_key`.
//
// Not here yet (IPP_PROTOCOL §2: auth, retries and TLS pinning are deferred): retries, TLS
// pinning of the provider certificate, SAM registry lookup of `base_url` and `provider_pk`.

use network_common::common::ipp::{
    BroadcastNotif, Commitment, DeliveryConfirm, FundingNotif, IppError, IppMessage, OpenBalanceAck,
    OpenBalanceRequest, Outpoint, PayHalfSign, SignedMessage, IPP_VERSION,
};
use network_common::transaction::Transaction;
use secp256k1::SecretKey;

use crate::wallet::escrow::{new_policy, own_xonly, EscrowError};
use network_common::crypto::escrow::EscrowPolicy;

#[derive(Debug)]
pub enum IppClientError {
    /// Connection, TLS or body-read failure.
    Http(String),
    /// The provider answered with an error status.
    Status { code: u16, body: String },
    /// Signature, signer, type or version of a message did not check out.
    Message(IppError),
    /// The answer is valid but is not what we asked about.
    Mismatch(String),
    /// A wallet-side policy check refused the provider's terms.
    Escrow(EscrowError),
}

impl std::fmt::Display for IppClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "provider unreachable: {e}"),
            Self::Status { code, body } => write!(f, "provider answered HTTP {code}: {body}"),
            Self::Message(e) => write!(f, "provider message refused: {e}"),
            Self::Mismatch(s) => write!(f, "provider answer does not match the request: {s}"),
            Self::Escrow(e) => write!(f, "provider terms refused: {e}"),
        }
    }
}

impl std::error::Error for IppClientError {}

impl From<IppError> for IppClientError {
    fn from(e: IppError) -> Self {
        Self::Message(e)
    }
}

impl From<EscrowError> for IppClientError {
    fn from(e: EscrowError) -> Self {
        Self::Escrow(e)
    }
}

/// An opened balance as the payer sees it: the provider's session and the policy both sides
/// computed. Fund `policy.hash()` (see `wallet::escrow::funding_output`), then call
/// [`IppClient::funding_notif`].
#[derive(Debug, Clone)]
pub struct OpenedBalance {
    pub session_id: String,
    pub policy: EscrowPolicy,
    pub ack: OpenBalanceAck,
}

pub struct IppClient {
    base: String,
    http: reqwest::Client,
    provider_pk: [u8; 32],
}

impl IppClient {
    /// `base_url` is the provider endpoint (no trailing path); `provider_pk` its registry key.
    pub fn new(base_url: &str, provider_pk: [u8; 32]) -> Self {
        Self { base: base_url.trim_end_matches('/').to_string(), http: reqwest::Client::new(), provider_pk }
    }

    fn url(&self, msg_type: &str) -> String {
        format!("{}/ipp/v1/{msg_type}", self.base)
    }

    async fn send<M: IppMessage>(&self, msg: &M, key: &SecretKey) -> Result<reqwest::Response, IppClientError> {
        let signed = SignedMessage::sign(msg, key)?;
        let resp = self
            .http
            .post(self.url(M::TYPE))
            .json(&signed)
            .send()
            .await
            .map_err(|e| IppClientError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(IppClientError::Status { code, body });
        }
        Ok(resp)
    }

    /// Send `msg` signed with `key`; open the provider's answer as `R` (signed by the provider).
    async fn call<M: IppMessage, R: IppMessage>(&self, msg: &M, key: &SecretKey) -> Result<R, IppClientError> {
        let resp = self.send(msg, key).await?;
        let signed: SignedMessage = resp.json().await.map_err(|e| IppClientError::Http(e.to_string()))?;
        let out: R = signed.open(Some(&self.provider_pk))?;
        Ok(out)
    }

    /// Open a balance. `tip_height` is the caller's own verified tip (never the provider's) and
    /// `min_lead_blocks` the room H must leave above it (return window + safety margin).
    pub async fn open_balance(
        &self,
        payer_key: &SecretKey,
        chain_id: u16,
        amount_atoms: u64,
        slots: u32,
        lock_blocks: u32,
        tip_height: u32,
        min_lead_blocks: u32,
    ) -> Result<OpenedBalance, IppClientError> {
        let req = OpenBalanceRequest {
            version: IPP_VERSION,
            chain_id,
            amount_atoms,
            slots,
            lock_blocks,
            payer_pk_hex: hex::encode(own_xonly(payer_key)),
        };
        let ack: OpenBalanceAck = self.call(&req, payer_key).await?;
        if ack.version != IPP_VERSION {
            return Err(IppError::UnsupportedVersion(ack.version).into());
        }
        if ack.provider_pk_hex != hex::encode(self.provider_pk) {
            return Err(IppClientError::Mismatch("the ack names a different provider key than the registry record".into()));
        }
        // The wallet's own checks (spec §5.1): valid keys, H leaves room above the tip.
        let policy = new_policy(payer_key, self.provider_pk, ack.unlock_height, tip_height, min_lead_blocks)?;
        if hex::encode(policy.hash()) != ack.policy_hash_hex {
            return Err(IppClientError::Mismatch("the provider's policy hash differs from the one computed here".into()));
        }
        Ok(OpenedBalance { session_id: ack.session_id.clone(), policy, ack })
    }

    /// Tell the provider the funding is in a block. The provider checks it through its own nodes.
    pub async fn funding_notif(
        &self,
        payer_key: &SecretKey,
        session_id: &str,
        funding_txid: [u8; 32],
        outpoints: Vec<Outpoint>,
    ) -> Result<(), IppClientError> {
        let msg = FundingNotif {
            version: IPP_VERSION,
            session_id: session_id.to_string(),
            funding_txid_hex: hex::encode(funding_txid),
            outpoints,
        };
        self.send(&msg, payer_key).await.map(|_| ())
    }

    /// Hand the provider the payer's half and get the commitment back. The commitment is
    /// checked against the payment that was sent: signer, request id, chain, the reserved
    /// outpoints (= the transaction's inputs), the amount, and the timing rules of
    /// `Commitment::check` against the escrow's H.
    pub async fn pay_half_sign(
        &self,
        payer_key: &SecretKey,
        msg: &PayHalfSign,
        policy: &EscrowPolicy,
        safety_margin: u32,
        now_unix: u64,
    ) -> Result<Commitment, IppClientError> {
        let tx_bytes = hex::decode(&msg.tx_hex).map_err(|_| IppClientError::Mismatch("tx_hex is not hex".into()))?;
        let tx = Transaction::deserialize_with_witnesses(&tx_bytes)
            .map_err(|e| IppClientError::Mismatch(format!("tx_hex does not parse: {e:?}")))?;
        let commitment: Commitment = self.call(msg, payer_key).await?;
        commitment.check(policy.unlock_height, safety_margin, now_unix)?;
        if commitment.payment_request_id != msg.payment_request_id {
            return Err(IppClientError::Mismatch("commitment is for another payment request".into()));
        }
        if commitment.chain_id != msg.chain_id {
            return Err(IppClientError::Mismatch("commitment is for another chain".into()));
        }
        let want: Vec<Outpoint> =
            tx.inputs.iter().map(|i| Outpoint { height: i.prev_height, output_idx: i.prev_output_idx }).collect();
        if commitment.escrow_outpoints != want {
            return Err(IppClientError::Mismatch("commitment reserves other escrow outputs than the payment spends".into()));
        }
        if tx.outputs.first().map(|o| o.value) != Some(commitment.amount_atoms) {
            return Err(IppClientError::Mismatch("commitment amount differs from the payment's first output".into()));
        }
        Ok(commitment)
    }

    /// Merchant side: mark the payment delivered. The provider completes the spend, broadcasts
    /// it and answers with the txid; the caller confirms the txid through its own nodes.
    pub async fn delivery_confirm(
        &self,
        merchant_key: &SecretKey,
        payment_request_id: &str,
        delivered_at_unix: u64,
    ) -> Result<BroadcastNotif, IppClientError> {
        let msg = DeliveryConfirm {
            version: IPP_VERSION,
            payment_request_id: payment_request_id.to_string(),
            delivered_at_unix,
        };
        let out: BroadcastNotif = self.call(&msg, merchant_key).await?;
        if out.payment_request_id != payment_request_id {
            return Err(IppClientError::Mismatch("broadcast notification is for another payment request".into()));
        }
        Ok(out)
    }
}
