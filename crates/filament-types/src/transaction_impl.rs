// filament-types/src/transaction.rs — transaction wire types.
//
// Bitcoin-style positional-input transaction (Shisha Network D2 wire
// format), needed by Filament to build, sign, and submit wallet
// transactions. Pure data + serialization — no chain-application logic.

use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    UnexpectedEof,
    TooManyInputs,
    TooManyOutputs,
    InvalidScript,
    IoError(String),
}

/// Header of an extension record: a typed, versioned prefix.
///
/// Type ranges: `0x0001..=0x0FFF` consensus, `0x1000..=0x1FFF` application,
/// `0x2000..` protocol / experimental.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionHeader {
    pub extension_type: u16,
    pub version: u16,
    pub payload_length: u32,
}

/// A typed payload attached to a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRecord {
    pub header: ExtensionHeader,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Txid(pub [u8; 32]);

impl std::fmt::Debug for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Txid({})", hex::encode(self.0))
    }
}

/// Positional transaction input — references an output by
/// `(prev_height, prev_output_idx)` rather than a txid hash lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_height: u32,
    pub prev_output_idx: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    /// x-only Schnorr public key (32 bytes, BIP-340 style). `[0u8; 32]` for
    /// OP_RETURN / unspendable outputs.
    pub recipient: [u8; 32],
}

/// Fixed 6-byte positional input for flat block-body packing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatInput {
    pub prev_height: u32,
    pub prev_output_idx: u16,
}

impl FlatInput {
    pub const SIZE: usize = 6;

    pub fn to_bytes(self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..4].copy_from_slice(&self.prev_height.to_le_bytes());
        out[4..6].copy_from_slice(&self.prev_output_idx.to_le_bytes());
        out
    }
}

/// Fixed 40-byte flat output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatOutput {
    pub value: u64,
    pub recipient: [u8; 32],
}

impl FlatOutput {
    pub const SIZE: usize = 40;

    pub fn to_bytes(self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&self.value.to_le_bytes());
        out[8..40].copy_from_slice(&self.recipient);
        out
    }
}

/// Per-input Schnorr authorization (SegWit-style separation from inputs[]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEntry {
    pub witness_data: Vec<u8>,
}

impl WitnessEntry {
    pub fn to_length_prefixed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.witness_data.len());
        out.extend_from_slice(&(self.witness_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.witness_data);
        out
    }

    pub fn from_length_prefixed_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 4 {
            return Err("witness entry too short for length");
        }
        let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if data.len() < 4 + len {
            return Err("witness entry payload too short");
        }
        Ok((
            Self { witness_data: data[4..4 + len].to_vec() },
            4 + len,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// There is one transaction version, `1`, for coinbases and spends alike.
    pub version: u8,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    #[serde(default)]
    pub expiration_height: u32,
    #[serde(default)]
    pub witnesses: Vec<WitnessEntry>,
    /// Extension records. Empty for a plain spend.
    #[serde(default)]
    pub extensions: Vec<ExtensionRecord>,
}

impl Transaction {
    pub fn new(version: u8, locktime: u32) -> Self {
        Transaction {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
            expiration_height: 0,
            witnesses: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }

    /// Wire format without witnesses: `version(1) | in_count(4) | inputs |
    /// out_count(4) | outputs | locktime(4) | expiration_height(4)`. Each input
    /// is `prev_height(4) | prev_output_idx(2) | script_len(4) = 0`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            bytes.extend_from_slice(&input.prev_height.to_le_bytes());
            bytes.extend_from_slice(&input.prev_output_idx.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes()); // script len always 0
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

    pub fn size(&self) -> usize {
        self.serialize().len()
    }

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

    /// `serialize()` output followed by `witness_count(4) | [len(4)||data]*`,
    /// and, only when the transaction has extension records, an extension
    /// section `ext_count(4) | [ext_type(2) | ext_version(2) | len(4) | payload]*`.
    /// A plain transaction's bytes are therefore unchanged.
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

    pub fn deserialize_with_witnesses(data: &[u8]) -> Result<Self, DeserializeError> {
        let mut tx = Self::deserialize(data)?;
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
        let rest = &remaining[offset..];
        if !rest.is_empty() {
            tx.extensions = decode_extension_section(rest)?;
        }
        Ok(tx)
    }

    // The transaction id is `Transaction::txid(chain_id)` in `txid.rs`
    // (VF-3: one id, BLAKE3, chain-separated). The old SHA256d id is gone.
}

fn read_u8<R: Read>(reader: &mut R) -> Result<u8, DeserializeError> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).map_err(|_| DeserializeError::UnexpectedEof)?;
    Ok(buf[0])
}

/// Decode the trailing extension section written by `serialize_with_witnesses`.
/// Rejects trailing bytes and absurd counts or lengths.
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

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, DeserializeError> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).map_err(|_| DeserializeError::UnexpectedEof)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, DeserializeError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).map_err(|_| DeserializeError::UnexpectedEof)?;
    Ok(u64::from_le_bytes(buf))
}

fn deserialize_input<R: Read>(reader: &mut R) -> Result<TxInput, DeserializeError> {
    let prev_height = read_u32(reader)?;
    let mut idx_buf = [0u8; 2];
    reader.read_exact(&mut idx_buf).map_err(|_| DeserializeError::UnexpectedEof)?;
    let prev_output_idx = u16::from_le_bytes(idx_buf);
    let script_len = read_u32(reader)?;
    if script_len > 10_000 {
        return Err(DeserializeError::InvalidScript);
    }
    if script_len > 0 {
        let mut buf = vec![0u8; script_len as usize];
        reader.read_exact(&mut buf).map_err(|_| DeserializeError::UnexpectedEof)?;
    }
    Ok(TxInput { prev_height, prev_output_idx })
}

fn deserialize_output<R: Read>(reader: &mut R) -> Result<TxOutput, DeserializeError> {
    let value = read_u64(reader)?;
    let mut recipient = [0u8; 32];
    reader.read_exact(&mut recipient).map_err(|_| DeserializeError::UnexpectedEof)?;
    Ok(TxOutput { value, recipient })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        let mut tx = Transaction::new(1, 0);
        tx.add_input(TxInput { prev_height: 5, prev_output_idx: 1 });
        tx.add_output(TxOutput { value: 1000, recipient: [7u8; 32] });
        tx
    }

    #[test]
    fn serialize_roundtrips() {
        let tx = sample_tx();
        let bytes = tx.serialize();
        let decoded = Transaction::deserialize(&bytes).unwrap();
        assert_eq!(decoded.serialize(), tx.serialize());
    }

    #[test]
    fn witness_wire_roundtrips() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![1, 2, 3, 4] });
        let bytes = tx.serialize_with_witnesses();
        let decoded = Transaction::deserialize_with_witnesses(&bytes).unwrap();
        assert_eq!(decoded.witnesses.len(), 1);
        assert_eq!(decoded.witnesses[0].witness_data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn txid_ignores_witnesses() {
        let mut tx = sample_tx();
        let txid_before = tx.txid(1);
        tx.witnesses.push(WitnessEntry { witness_data: vec![9, 9] });
        assert_eq!(tx.txid(1), txid_before);
    }

    #[test]
    fn version_is_one_byte_on_the_wire() {
        let tx = sample_tx();
        let b = tx.serialize();
        assert_eq!(b[0], 1, "first byte is the version");
        // version(1) in_count(4) input(10) out_count(4) output(40) locktime(4) expiration(4)
        assert_eq!(b.len(), 1 + 4 + 10 + 4 + 40 + 4 + 4);
    }

    fn ext(t: u16, v: u16, payload: &[u8]) -> ExtensionRecord {
        ExtensionRecord {
            header: ExtensionHeader { extension_type: t, version: v, payload_length: payload.len() as u32 },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn plain_transaction_bytes_have_no_extension_section() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![1, 2, 3] });
        let plain = tx.serialize_with_witnesses();
        tx.extensions.push(ext(0x1234, 1, &[9, 9]));
        let with_ext = tx.serialize_with_witnesses();
        assert!(with_ext.len() > plain.len());
        assert_eq!(&with_ext[..plain.len()], &plain[..], "extension section is purely appended");
    }

    #[test]
    fn extension_section_roundtrips() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![5; 65] });
        tx.extensions = vec![ext(0x1234, 1, &[1, 2, 3]), ext(0x0001, 1, &[0u8; 9])];
        let back = Transaction::deserialize_with_witnesses(&tx.serialize_with_witnesses()).unwrap();
        assert_eq!(back.extensions, tx.extensions);
        assert_eq!(back.witnesses.len(), 1);
    }

    #[test]
    fn malformed_extension_sections_are_rejected() {
        let mut tx = sample_tx();
        tx.witnesses.push(WitnessEntry { witness_data: vec![1] });
        tx.extensions = vec![ext(0x1234, 1, &[1, 2, 3])];
        let good = tx.serialize_with_witnesses();
        assert!(Transaction::deserialize_with_witnesses(&good).is_ok());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(Transaction::deserialize_with_witnesses(&trailing).is_err(), "trailing byte");
        assert!(Transaction::deserialize_with_witnesses(&good[..good.len() - 1]).is_err(), "truncated payload");
    }

    #[test]
    fn coinbase_has_no_inputs() {
        let tx = Transaction::new(1, 0);
        assert!(tx.is_coinbase());
        assert!(!sample_tx().is_coinbase());
    }
}
