// ============================================================================
// transaction/serialize.rs - Transaction Serialization
// ============================================================================
//
// Legacy v4 beacon-block wire format: positional inputs/outputs without witnesses.
// Authorization lives in ShardBlockBody::witnesses[] (flat-body model).
//
// ============================================================================

use std::io::Cursor;
use super::types::{Transaction, DeserializeError, ExtensionHeader, ExtensionRecord, WitnessEntry};
use super::helpers::*;

impl Transaction {
    /// Serialize with witnesses appended (used for mempool submission wire format).
    ///
    /// `serialize()` output (used for txid) followed by:
    /// `witness_count(4) | [len(4) || data]*witness_count`.
    ///
    /// When `extensions` is non-empty, an extension section follows (VF-3):
    /// `ext_count(4) | [ext_type(2) | ext_version(2) | len(4) | payload]*ext_count`.
    /// It is omitted when there are no extensions, so a plain transaction's
    /// bytes are unchanged.
    ///
    /// Additive over `serialize()` — a plain `deserialize()` stops after
    /// `expiration_height` and ignores the trailing sections.
    pub fn serialize_with_witnesses(&self) -> Vec<u8> {
        let mut bytes = self.serialize();
        bytes.extend_from_slice(&(self.witnesses.len() as u32).to_le_bytes());
        for w in &self.witnesses {
            bytes.extend_from_slice(&w.to_length_prefixed_bytes());
        }
        if !self.extensions.is_empty() {
            bytes.extend_from_slice(&(self.extensions.len() as u32).to_le_bytes());
            for e in &self.extensions {
                bytes.extend_from_slice(&e.header.extension_type.to_le_bytes());
                bytes.extend_from_slice(&e.header.version.to_le_bytes());
                bytes.extend_from_slice(&(e.payload.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&e.payload);
            }
        }
        bytes
    }

    /// Deserialize, then read a trailing witness section if present.
    ///
    /// Runs the same logic as [`Self::deserialize`] first; if the cursor still has
    /// remaining bytes afterward, reads `witness_count(4)` and that many
    /// length-prefixed `WitnessEntry` records. If the cursor is already exhausted
    /// (the legacy, witness-less wire format), behaves exactly like `deserialize`.
    pub fn deserialize_with_witnesses(data: &[u8]) -> Result<Self, DeserializeError> {
        let mut tx = Self::deserialize(data)?;

        // Recompute how many bytes deserialize() consumed by re-serializing the
        // witness-less form; anything beyond that is the witness section.
        let consumed = tx.serialize().len();
        if data.len() <= consumed {
            return Ok(tx);
        }

        let mut cursor = Cursor::new(&data[consumed..]);
        let witness_count = read_u32(&mut cursor)?;
        if witness_count > 100_000 {
            return Err(DeserializeError::TooManyInputs);
        }

        let remaining = &data[consumed + 4..];
        let mut offset = 0usize;
        let mut witnesses = Vec::with_capacity(witness_count as usize);
        for _ in 0..witness_count {
            let (entry, used) = WitnessEntry::from_length_prefixed_bytes(&remaining[offset..])
                .map_err(|_| DeserializeError::IoError("invalid witness section".to_string()))?;
            offset += used;
            witnesses.push(entry);
        }

        tx.witnesses = witnesses;

        // Optional extension section (VF-3).
        let rest = &remaining[offset..];
        if !rest.is_empty() {
            tx.extensions = decode_extension_section(rest)?;
        }
        Ok(tx)
    }

    /// Serialize transaction without witness (mempool / txid preimage).
    ///
    /// Format: version(1) | input_count(4) | inputs | output_count(4) | outputs
    ///       | locktime(4) | expiration_height(4)
    ///
    /// `expiration_height` must be on the wire: TX-5/TX-6 sighash commits to it
    /// (NC-93 — previously serialize stopped at locktime and deserialize forced
    /// `expiration_height = 0`, so every signed mempool tx with a non-zero expiry
    /// failed Schnorr verify on the receiving node).
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.version);
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        for input in &self.inputs {
            bytes.extend_from_slice(&input.prev_height.to_le_bytes());
            bytes.extend_from_slice(&input.prev_output_idx.to_le_bytes());
            // Script length always 0 — authorization in witnesses[]
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }

        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());

        for output in &self.outputs {
            bytes.extend_from_slice(&output.value.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }

        bytes.extend_from_slice(&self.locktime.to_le_bytes());
        bytes.extend_from_slice(&self.expiration_height.to_le_bytes());

        bytes
    }

    /// Serialized byte length (witness excluded).
    pub fn size(&self) -> usize {
        self.serialize().len()
    }

    /// Deserialize a transaction from bytes (legacy v4 format).
    pub fn deserialize(data: &[u8]) -> Result<Self, DeserializeError> {
        let mut cursor = Cursor::new(data);

        let version = read_u8(&mut cursor)?;

        let input_count = read_u32(&mut cursor)?;
        if input_count > 100_000 {
            return Err(DeserializeError::TooManyInputs);
        }

        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            inputs.push(deserialize_input(&mut cursor)?);
        }

        let output_count = read_u32(&mut cursor)?;
        if output_count > 100_000 {
            return Err(DeserializeError::TooManyOutputs);
        }

        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            outputs.push(deserialize_output(&mut cursor)?);
        }

        let locktime = read_u32(&mut cursor)?;
        let expiration_height = read_u32(&mut cursor)?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            locktime,
            expiration_height,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        })
    }
}


/// Decode the trailing extension section written by `serialize_with_witnesses`.
/// Rejects trailing bytes and absurd counts/lengths.
fn decode_extension_section(data: &[u8]) -> Result<Vec<ExtensionRecord>, DeserializeError> {
    let bad = |m: &str| DeserializeError::IoError(format!("invalid extension section: {m}"));
    if data.len() < 4 {
        return Err(bad("truncated count"));
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if count > 1_000 {
        return Err(bad("too many records"));
    }
    let mut pos = 4usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < pos + 8 {
            return Err(bad("truncated header"));
        }
        let extension_type = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        let version = u16::from_le_bytes(data[pos + 2..pos + 4].try_into().unwrap());
        let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if data.len() < pos + len {
            return Err(bad("truncated payload"));
        }
        out.push(ExtensionRecord {
            header: ExtensionHeader { extension_type, version, payload_length: len as u32 },
            payload: data[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    if pos != data.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod witness_wire_tests {

    #[test]
    fn round_trips_extensions_after_witnesses() {
        use crate::transaction::{ExtensionHeader, ExtensionRecord};
        let mut tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
            expiration_height: 0,
            witnesses: vec![WitnessEntry { witness_data: vec![9; 3] }],
            extensions: vec![ExtensionRecord {
                header: ExtensionHeader { extension_type: 0x1234, version: 1, payload_length: 2 },
                payload: vec![5, 6],
            }],
        };
        let decoded = Transaction::deserialize_with_witnesses(&tx.serialize_with_witnesses()).unwrap();
        assert_eq!(decoded.extensions, tx.extensions);
        assert_eq!(decoded.witnesses, tx.witnesses);
        tx.extensions.clear();
        let decoded = Transaction::deserialize_with_witnesses(&tx.serialize_with_witnesses()).unwrap();
        assert!(decoded.extensions.is_empty());
    }
    use super::*;
    use super::super::types::{TxInput, TxOutput};

    fn sample_tx() -> Transaction {
        let mut tx = Transaction::new(1, 0);
        tx.add_input(TxInput { prev_height: 5, prev_output_idx: 1 });
        tx.add_output(TxOutput { value: 1000, recipient: [7u8; 32] });
        tx
    }

    #[test]
    fn round_trips_with_zero_witnesses() {
        let tx = sample_tx();
        let bytes = tx.serialize_with_witnesses();
        let decoded = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert!(decoded.witnesses.is_empty());
        assert_eq!(decoded.serialize(), tx.serialize());
    }

    #[test]
    fn round_trips_with_one_witness() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![1, 2, 3, 4] });
        let bytes = tx.serialize_with_witnesses();
        let decoded = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert_eq!(decoded.witnesses.len(), 1);
        assert_eq!(decoded.witnesses[0].witness_data, vec![1, 2, 3, 4]);
    }

    /// NC-93: mempool wire must preserve `expiration_height` (TX-5 sighash field).
    #[test]
    fn nc93_mempool_wire_preserves_expiration_height() {
        let mut tx = sample_tx();
        tx.locktime = 20;
        tx.expiration_height = 164;
        tx.witnesses.push(WitnessEntry {
            witness_data: vec![0x01; 65],
        });
        let bytes = tx.serialize_with_witnesses();
        let decoded = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert_eq!(decoded.locktime, 20);
        assert_eq!(
            decoded.expiration_height, 164,
            "expiration_height must survive serialize_with_witnesses round-trip"
        );
        assert_eq!(decoded.witnesses.len(), 1);
        assert_eq!(decoded.witnesses[0].witness_data, vec![0x01; 65]);
    }

    #[test]
    fn round_trips_with_n_witnesses() {
        let mut tx = sample_tx();
        for i in 0..5u8 {
            tx.witnesses.push(WitnessEntry { witness_data: vec![i; (i as usize) + 1] });
        }
        let bytes = tx.serialize_with_witnesses();
        let decoded = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert_eq!(decoded.witnesses.len(), 5);
        for i in 0..5u8 {
            assert_eq!(decoded.witnesses[i as usize].witness_data, vec![i; (i as usize) + 1]);
        }
    }

    #[test]
    fn plain_deserialize_ignores_witness_section_and_matches_txid() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![9, 9, 9] });
        let bytes = tx.serialize_with_witnesses();

        // Legacy deserialize() must still work on witness-carrying bytes and
        // yield an empty-witness tx with an identical txid to the witness-less form.
        let legacy = Transaction::deserialize(&bytes).unwrap();
        assert!(legacy.witnesses.is_empty());
        assert_eq!(legacy.serialize(), tx.serialize());
    }
}
