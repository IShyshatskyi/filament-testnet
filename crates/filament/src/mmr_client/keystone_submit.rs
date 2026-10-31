// src/mmr_client/keystone_submit.rs
//
// Submit a signed transaction to Keystone the way Keystone accepts it: raw
// `Transaction::serialize_with_witnesses` bytes to `POST /mempool/submit?shard=N`
// (`/mempool/submit/beacon` for the beacon chain). Used by wallet sends, raw broadcasts and
// escrow recovery. (Keystone's `/wallet/send` is a stub that returns a zero txid and
// `/wallet/broadcast` does not exist — FIL-SEND-1 / FIL-BCAST-1.)

use serde_json::Value;

/// Post `bytes` to the first endpoint that accepts them. MNT-7 propagation redundancy, not a
/// trust check: one accept is enough. The error carries the last refusal (Keystone answers
/// `{"status":"rejected","reason":…}`).
pub async fn submit_raw_tx(
    http: &reqwest::Client,
    endpoints: &[String],
    shard_id: Option<u16>,
    bytes: Vec<u8>,
) -> Result<Value, String> {
    if endpoints.is_empty() {
        return Err("no Keystone endpoint configured".into());
    }
    let mut last = String::new();
    for ep in endpoints {
        let base = ep.trim_end_matches('/');
        let url = match shard_id {
            Some(s) => format!("{base}/mempool/submit?shard={s}"),
            None => format!("{base}/mempool/submit/beacon"),
        };
        match http
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(bytes.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                let ok = resp.status().is_success();
                let status = resp.status().as_u16();
                let body: Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({ "status": status }));
                if ok {
                    return Ok(body);
                }
                last = format!("{base}: {body}");
            }
            Err(e) => last = format!("{base}: {e}"),
        }
    }
    Err(format!("no Keystone accepted the transaction ({last})"))
}

/// Broadcast a signed transaction given as hex. The bytes must be
/// `Transaction::serialize_with_witnesses` (what `/mempool/submit` decodes); they are parsed
/// here first so a wrong format is refused with a clear message instead of a node error.
/// Returns Keystone's answer with `txid` (chain-separated, VF-3) filled in.
pub async fn broadcast_hex(
    http: &reqwest::Client,
    endpoints: &[String],
    shard_id: u16,
    tx_hex: &str,
) -> Result<Value, String> {
    let bytes = hex::decode(tx_hex.trim()).map_err(|_| "transaction must be hex".to_string())?;
    let tx = common_types::transaction::Transaction::deserialize_with_witnesses(&bytes).map_err(|e| {
        format!("not a signed transaction (expected serialize_with_witnesses bytes): {e:?}")
    })?;
    if tx.witnesses.len() != tx.inputs.len() {
        return Err(format!("{} inputs but {} witnesses — sign every input first", tx.inputs.len(), tx.witnesses.len()));
    }
    let txid = hex::encode(tx.txid(common_types::transaction::shard_chain_id(shard_id)).0);
    let mut answer = submit_raw_tx(http, endpoints, Some(shard_id), bytes).await?;
    if let Some(obj) = answer.as_object_mut() {
        obj.entry("txid").or_insert(Value::String(txid));
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr_client::filament_wallet::{FilamentWallet, SendRequest, UtxoEntry};
    use axum::{body::Bytes, extract::Query, routing::post, Json, Router};
    use common_types::common::utxo::ForkUtxoOverlay;
    use common_types::common::validation::transactions::{validate_transaction_for_mempool, MempoolAdmissionParams};
    use common_types::common::validation::BlockValidationUtxo;
    use common_types::transaction::{shard_chain_id, FlatOutput, Transaction};
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(Option<u16>, Vec<u8>)>>>;

    /// A fake Keystone `/mempool/submit` that records what it receives.
    async fn fake_keystone(seen: Seen) -> String {
        let app = Router::new().route(
            "/mempool/submit",
            post(move |q: Query<std::collections::HashMap<String, String>>, body: Bytes| {
                let seen = seen.clone();
                async move {
                    let shard = q.get("shard").and_then(|s| s.parse().ok());
                    seen.lock().unwrap().push((shard, body.to_vec()));
                    Json(serde_json::json!({ "status": "accepted", "shard": shard }))
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn utxo(shard_id: u16, height: u32, idx: u16, coins: f64) -> UtxoEntry {
        UtxoEntry { height, output_idx: idx, value: coins, confirmations: 3, coinbase: false, shard_id }
    }

    /// FIL-SEND-1: the wallet signs locally, the node gets raw bytes it admits, and only the
    /// requested shard's outputs are spent.
    #[tokio::test]
    async fn send_is_signed_locally_and_submitted_raw() {
        let seen: Seen = Arc::default();
        let ep = fake_keystone(seen.clone()).await;
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[0x33; 32]).unwrap();
        let me = bitcoin::secp256k1::Keypair::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &key)
            .x_only_public_key().0.serialize();
        let mut wallet = FilamentWallet::new(String::new(), None);
        wallet.attach_hot_key(key).unwrap();
        wallet.set_keystone_endpoints(vec![ep]);
        // Shard 1 has more money, but the send is on shard 0.
        wallet.set_utxos(vec![utxo(0, 40, 0, 0.6), utxo(1, 41, 0, 50.0), utxo(0, 42, 1, 0.5)]);

        let req = SendRequest { to: "77".repeat(32), amount_atoms: 100_000_000, fee_atoms: 10_000, shard_id: 0 };
        let resp = wallet.submit_transaction(&req, 50).await.unwrap();
        assert_eq!(resp.status, "accepted");

        let (shard, bytes) = seen.lock().unwrap()[0].clone();
        assert_eq!(shard, Some(0));
        let tx = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert_eq!(resp.txid, hex::encode(tx.txid(shard_chain_id(0)).0));
        let mut spent: Vec<(u32, u16)> = tx.inputs.iter().map(|i| (i.prev_height, i.prev_output_idx)).collect();
        spent.sort();
        assert_eq!(spent, vec![(40, 0), (42, 1)], "shard 0 outputs only");

        let mut u = ForkUtxoOverlay::new();
        u.add(40, 0, FlatOutput { value: 60_000_000, recipient: me });
        u.add(42, 1, FlatOutput { value: 50_000_000, recipient: me });
        validate_transaction_for_mempool(&tx, BlockValidationUtxo::ReorgBuffer(&u), MempoolAdmissionParams::production(50, 0, 1024, shard_chain_id(0)))
            .expect("node admits the locally signed send");

        // Not enough on shard 0 alone: refused, never topped up from shard 1.
        let big = SendRequest { amount_atoms: 2_000_000_000, ..req };
        assert!(wallet.submit_transaction(&big, 50).await.unwrap_err().contains("Insufficient"));
    }

    #[tokio::test]
    async fn send_without_key_is_refused_and_broadcast_checks_format() {
        let seen: Seen = Arc::default();
        let ep = fake_keystone(seen.clone()).await;
        let wallet = FilamentWallet::new("aa".repeat(32), None);
        let req = SendRequest { to: "77".repeat(32), amount_atoms: 1, fee_atoms: 1, shard_id: 0 };
        assert!(wallet.submit_transaction(&req, 5).await.unwrap_err().contains("no signing key"));

        let http = reqwest::Client::new();
        assert!(broadcast_hex(&http, &[ep.clone()], 0, "zz").await.unwrap_err().contains("hex"));
        assert!(broadcast_hex(&http, &[ep.clone()], 0, "deadbeef").await.unwrap_err().contains("not a signed transaction"));
        assert!(seen.lock().unwrap().is_empty(), "nothing malformed reaches the node");
        assert!(submit_raw_tx(&http, &[], Some(0), vec![1]).await.unwrap_err().contains("no Keystone"));
    }
}
