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
    /// Sign a transaction, returning one `WitnessEntry` per input.
    ///
    /// `keys` must have the same length as `tx.inputs`. Each key signs the
    /// sighash for its corresponding input using BIP-340 Schnorr.
    pub fn sign_transaction(
        tx: &Transaction,
        keys: &[SecretKey],
        chain_id: u8,
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
            let sighash = Self::sighash(tx, i, chain_id)?;
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

    /// Compute the Shisha sighash for one input.
    ///
    /// Preimage (all LE):
    ///   chain_id(u8) || tx_version(u8) || locktime(u32) || expiration_height(u32)
    ///   || n_inputs(u32) || [prev_height(u32) + prev_output_idx(u16)] × n
    ///   || n_outputs(u32) || [value(u64) + recipient([u8;32])] × m
    ///   || input_index(u32)
    ///
    /// Notes:
    /// - `chain_id` is a u8 shard identifier providing cross-shard replay protection.
    /// - `tx_version` is cast to u8; the u32 field in `Transaction` is legacy and will
    ///   be narrowed to u8 in a future struct migration.
    /// - `expiration_height` commits the CV-11/TE-2 expiry window so it cannot be
    ///   stripped post-signing (design §20.5).
    /// - Extension data (e.g., ShortAddrHints) will be appended before `input_index`
    ///   once `Transaction` gains an `extensions: Vec<ExtensionRecord>` field (SAM phase).
    /// - Prevout values will be appended for Ledger hardware wallet fee display once
    ///   `sign_transaction` receives UTXO value inputs.
    pub fn sighash(
        tx: &Transaction,
        input_index: usize,
        chain_id: u8,
    ) -> Result<[u8; 32], String> {
        let inputs: Vec<common_types::transaction::FlatInput> = tx
            .inputs
            .iter()
            .map(|i| common_types::transaction::FlatInput {
                prev_height: i.prev_height,
                prev_output_idx: i.prev_output_idx,
            })
            .collect();
        let outputs: Vec<common_types::transaction::FlatOutput> = tx
            .outputs
            .iter()
            .map(|o| common_types::transaction::FlatOutput {
                value: o.value,
                recipient: o.recipient,
            })
            .collect();
        common_types::common::crypto::flat_tx_sighash(
            chain_id,
            tx.version.min(u32::from(u8::MAX)) as u8,
            tx.locktime,
            tx.expiration_height,
            &inputs,
            &outputs,
            input_index as u32,
        )
        .map_err(|e| format!("{e}"))
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
        }
    }

    #[test]
    fn sign_transaction_rejects_key_count_mismatch() {
        let tx = make_tx(2, 1);
        let secp = TestSecp256k1::new();
        let key = SecretKey::new(&mut TestOsRng);
        let _ = &secp;
        let err = SchnorrSigner::sign_transaction(&tx, &[key], 0).unwrap_err();
        assert!(err.contains("key count"));
    }

    #[test]
    fn sign_transaction_produces_one_witness_per_input() {
        let tx = make_tx(2, 1);
        let keys = vec![SecretKey::new(&mut TestOsRng), SecretKey::new(&mut TestOsRng)];
        let witnesses = SchnorrSigner::sign_transaction(&tx, &keys, 0).unwrap();
        assert_eq!(witnesses.len(), 2);
        for w in &witnesses {
            assert_eq!(w.witness_data.len(), 65);
            assert_eq!(w.witness_data[0], 0x01);
        }
    }

    #[test]
    fn sighash_differs_by_chain_id() {
        let tx = make_tx(1, 1);
        let h0 = SchnorrSigner::sighash(&tx, 0, 0).unwrap();
        let h1 = SchnorrSigner::sighash(&tx, 0, 1).unwrap();
        assert_ne!(h0, h1, "chain_id must provide cross-shard replay protection");
    }
}
