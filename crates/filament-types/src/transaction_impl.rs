// filament-types/src/transaction.rs — transaction wire types.
//
// Bitcoin-style positional-input transaction (Shisha Network D2 wire
// format), needed by Filament to build, sign, and submit wallet
// transactions. Pure data + serialization — no chain-application logic.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

#[derive(Debug, PartialEq, Eq)]
pub enum DeserializeError {
    UnexpectedEof,
    TooManyInputs,
    TooManyOutputs,
    InvalidScript,
    IoError(String),
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
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
    #[serde(default)]
    pub expiration_height: u32,
    #[serde(default)]
    pub witnesses: Vec<WitnessEntry>,
}

impl Transaction {
    pub fn new(version: u32, locktime: u32) -> Self {
        Transaction {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime,
            expiration_height: 0,
            witnesses: Vec::new(),
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

    /// Legacy wire format (no witnesses): used for txid and as the sighash
    /// input basis. `version(4) | in_count(4) | inputs | out_count(4) |
    /// outputs | locktime(4) | expiration_height(4)`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
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
        let version = read_u32(&mut cursor)?;

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
        })
    }

    /// `serialize()` output followed by `witness_count(4) | [len(4)||data]*`.
    pub fn serialize_with_witnesses(&self) -> Vec<u8> {
        let mut bytes = self.serialize();
        bytes.extend_from_slice(&(self.witnesses.len() as u32).to_le_bytes());
        for w in &self.witnesses {
            bytes.extend_from_slice(&w.to_length_prefixed_bytes());
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
        Ok(tx)
    }

    /// SHA256d of the witness-less wire serialization (BIP-141-style
    /// malleability fix: witness data never affects txid).
    pub fn txid(&self) -> Txid {
        let serialized = self.serialize();
        let first = Sha256::digest(&serialized);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        Txid(out)
    }
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
        let txid_before = tx.txid();
        tx.witnesses.push(WitnessEntry { witness_data: vec![9, 9] });
        assert_eq!(tx.txid().0, txid_before.0);
    }

    #[test]
    fn coinbase_has_no_inputs() {
        let tx = Transaction::new(1, 0);
        assert!(tx.is_coinbase());
        assert!(!sample_tx().is_coinbase());
    }
}
