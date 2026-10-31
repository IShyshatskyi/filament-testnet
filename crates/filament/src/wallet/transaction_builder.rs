// src/wallet/transaction_builder.rs
//
// Trimmed 2026-07-04 (RF-20 follow-up): this file used to also hold
// `TransactionBuilder`/`TransactionSigner`/`TransactionHelper`, built on top
// of the dead `MultiShardWallet`/`WalletManager`/`AddressConfig` subsystem
// (see docs/reports/RF-19_RF-20_Completion_Report.md §3 for the full history
// — that subsystem predates the FV-3 flat-vector migration and was never
// updated to match it). Those three types had zero callers outside their own
// tests and were deleted along with the rest of that subsystem.
// `SchnorrSigner` is the one real, load-bearing piece of this file — it's
// used directly by `mmr_client::filament_wallet`, which builds its own
// transactions against the current flat-vector `Transaction`/`WitnessEntry`
// types without going through the deleted builder.

use common_types::transaction::types::{Transaction, WitnessEntry};
use bitcoin::secp256k1::{Secp256k1, Message, SecretKey, Keypair};
use bitcoin::secp256k1::rand::rngs::OsRng;

// ── FA-13: Schnorr signing path (FV-W witnesses[] architecture) ──────────────

/// Signs transactions using Schnorr signatures, producing `WitnessEntry` items
/// for the `ShardBlockBody::witnesses[]` vector (SegWit-style separation).
///
/// Wire format per input: `0x01` (Schnorr type) || 64-byte Schnorr sig.
pub struct SchnorrSigner;

impl SchnorrSigner {
    /// Sign a transaction with sighash v2, returning one `WitnessEntry` per
    /// input (TX-5). `tx.version` must be 2 (TX-11).
    ///
    /// `keys[i]` signs input `i`. `prevouts[i]` is the `(value, recipient)` of
    /// the output input `i` spends; they are committed, so a wrong value
    /// makes every signature invalid.
    pub fn sign_transaction(
        tx: &Transaction,
        keys: &[SecretKey],
        chain_id: u16,
        prevouts: &[(u64, [u8; 32])],
    ) -> Result<Vec<WitnessEntry>, String> {
        if prevouts.len() != tx.inputs.len() {
            return Err(format!(
                "prevout count {} != input count {}",
                prevouts.len(), tx.inputs.len()
            ));
        }
        let txid = tx.txid(chain_id).0;
        let prev = common_types::common::crypto::prevouts_hash(prevouts);
        Self::sign_with(tx, keys, |i| {
            Ok(common_types::common::crypto::sighash_v2(&txid, &prev, i as u32))
        })
    }

    /// The sighash v2 for input `input_index`.
    pub fn sighash(
        tx: &Transaction,
        input_index: usize,
        chain_id: u16,
        prevouts: &[(u64, [u8; 32])],
    ) -> [u8; 32] {
        common_types::common::crypto::sighash_v2(
            &tx.txid(chain_id).0,
            &common_types::common::crypto::prevouts_hash(prevouts),
            input_index as u32,
        )
    }

    fn sign_with(
        tx: &Transaction,
        keys: &[SecretKey],
        sighash_for: impl Fn(usize) -> Result<[u8; 32], String>,
    ) -> Result<Vec<WitnessEntry>, String> {
        if tx.inputs.len() != keys.len() {
            return Err(format!(
                "key count {} != input count {}",
                keys.len(), tx.inputs.len()
            ));
        }
        let secp = Secp256k1::new();
        let mut witnesses = Vec::with_capacity(keys.len());

        for (i, key) in keys.iter().enumerate() {
            let sighash = sighash_for(i)?;
            let msg = Message::from_digest(sighash);
            let keypair = Keypair::from_secret_key(&secp, key);
            let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut OsRng);

            // witness_data = 0x01 (type=Schnorr) || 64 bytes
            let mut data = Vec::with_capacity(65);
            data.push(0x01u8);
            data.extend_from_slice(sig.as_ref());
            witnesses.push(WitnessEntry { witness_data: data });
        }
        Ok(witnesses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng as TestOsRng;
    use bitcoin::secp256k1::Secp256k1 as TestSecp256k1;
    use common_types::transaction::types::{TxInput, TxOutput};

    fn make_tx(n_inputs: usize, n_outputs: usize) -> Transaction {
        Transaction {
            version: 1,
            inputs: (0..n_inputs)
                .map(|i| TxInput { prev_height: 1, prev_output_idx: i as u16 })
                .collect(),
            outputs: (0..n_outputs)
                .map(|_| TxOutput { value: 100, recipient: [7u8; 32] })
                .collect(),
            locktime: 0,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn sign_transaction_rejects_key_count_mismatch() {
        let tx = make_tx(2, 1);
        let secp = TestSecp256k1::new();
        let key = SecretKey::new(&mut TestOsRng);
        let _ = &secp;
        let err = SchnorrSigner::sign_transaction(&tx, &[key], 0, &[(1, [7u8; 32]); 2]).unwrap_err();
        assert!(err.contains("key count"));
    }

    #[test]
    fn sign_transaction_produces_one_witness_per_input() {
        let tx = make_tx(2, 1);
        let keys = vec![SecretKey::new(&mut TestOsRng), SecretKey::new(&mut TestOsRng)];
        let witnesses = SchnorrSigner::sign_transaction(&tx, &keys, 0, &[(1, [7u8; 32]); 2]).unwrap();
        assert_eq!(witnesses.len(), 2);
        for w in &witnesses {
            assert_eq!(w.witness_data.len(), 65);
            assert_eq!(w.witness_data[0], 0x01);
        }
    }

    #[test]
    fn sighash_differs_by_chain_id() {
        let tx = make_tx(1, 1);
        let h0 = SchnorrSigner::sighash(&tx, 0, 0, &[(1, [7u8; 32])]);
        let h1 = SchnorrSigner::sighash(&tx, 0, 1, &[(1, [7u8; 32])]);
        assert_ne!(h0, h1, "chain_id must provide cross-shard replay protection");
    }

    /// A signature from this signer passes the node's own CV-70 admission
    /// (sighash v2), and one signed over wrong spent values is refused.
    #[test]
    fn v2_signature_verifies_on_node_validator() {
        use common_types::common::utxo::ForkUtxoOverlay;
        use common_types::common::validation::transactions::{
            validate_transaction_for_mempool, MempoolAdmissionParams,
        };
        use common_types::common::validation::BlockValidationUtxo;
        use common_types::transaction::{shard_chain_id, FlatOutput};

        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[0x44u8; 32]).unwrap();
        let recipient = Keypair::from_secret_key(&secp, &key).x_only_public_key().0.serialize();
        let mut utxo = ForkUtxoOverlay::new();
        utxo.add(0, 0, FlatOutput { value: 10_000, recipient });

        let mut tx = make_tx(1, 1);
        tx.version = 1;
        tx.inputs[0] = TxInput { prev_height: 0, prev_output_idx: 0 };
        tx.outputs[0] = TxOutput { value: 9_000, recipient };
        let chain_id = shard_chain_id(0);
        tx.witnesses = SchnorrSigner::sign_transaction(&tx, &[key], chain_id, &[(10_000, recipient)]).unwrap();

        let params = MempoolAdmissionParams::production(1, 0, 1024, chain_id);
        validate_transaction_for_mempool(&tx, BlockValidationUtxo::ReorgBuffer(&utxo), params)
            .expect("signature must verify on the node");
        // A signature made for different spent values must not verify (prevouts are committed).
        let mut bad = tx.clone();
        bad.witnesses = SchnorrSigner::sign_transaction(&bad, &[key], chain_id, &[(9_999, recipient)]).unwrap();
        assert!(validate_transaction_for_mempool(&bad, BlockValidationUtxo::ReorgBuffer(&utxo), params).is_err());

        let err = SchnorrSigner::sign_transaction(&tx, &[key], chain_id, &[]).unwrap_err();
        assert!(err.contains("prevout count"));
    }
}
