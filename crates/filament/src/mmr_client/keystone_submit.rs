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


