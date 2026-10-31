// ============================================================================
// transaction/types.rs - Core Transaction Types
// ============================================================================
//
// PURPOSE:
// Define core transaction data structures:
// - Txid: Transaction identifier
// - TxInput: Transaction input (references previous output)
// - TxOutput: Transaction output (creates new UTXO)
// - Transaction: Complete transaction with inputs, outputs, and optional witness
//
// BITCOIN COMPATIBILITY:
// - Follows Bitcoin transaction structure
// - Supports legacy and SegWit formats
// - Compatible with Bitcoin consensus rules
//
// ============================================================================

use serde::{Serialize, Deserialize};
use std::fmt;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Deserialization error types
/// 
/// Represents all possible failures when deserializing transaction data
/// from binary format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeserializeError {
    /// Unexpected end of data while reading
    UnexpectedEof,
    
    /// Invalid varint encoding (malformed compact size)
    InvalidVarint,
    
    /// Invalid transaction version number
    InvalidVersion,
    
    /// Invalid locktime value
    InvalidLocktime,
    
    /// Too many inputs (exceeds safety limit of 100,000)
    TooManyInputs,
    
    /// Too many outputs (exceeds safety limit of 100,000)
    TooManyOutputs,
    
    /// Invalid script data (exceeds 10,000 bytes)
    InvalidScript,
    
    /// Generic I/O error with description
    IoError(String),
}

impl std::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DeserializeError::UnexpectedEof => write!(f, "Unexpected end of data"),
            DeserializeError::InvalidVarint => write!(f, "Invalid varint encoding"),
            DeserializeError::InvalidVersion => write!(f, "Invalid transaction version"),
            DeserializeError::InvalidLocktime => write!(f, "Invalid locktime"),
            DeserializeError::TooManyInputs => write!(f, "Too many inputs (>100,000)"),
            DeserializeError::TooManyOutputs => write!(f, "Too many outputs (>100,000)"),
            DeserializeError::InvalidScript => write!(f, "Invalid script data (>10,000 bytes)"),
            DeserializeError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for DeserializeError {}

// ============================================================================
// TRANSACTION IDENTIFIER
// ============================================================================

/// Transaction ID - SHA256d hash of serialized transaction
/// 
/// The txid is the double-SHA256 hash of the transaction data.
/// For SegWit transactions, witness data is excluded (malleability fix).
/// 
/// Properties:
/// - 32 bytes (256 bits)
/// - Deterministic (same transaction = same txid)
/// - Cryptographically secure (collision-resistant)
/// - Used as key in UTXO set
/// 
/// Bitcoin Compatibility:
/// - Matches Bitcoin's txid calculation
/// - Excludes witness data (BIP 141)
/// - Little-endian byte order when displayed as hex
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Txid(pub [u8; 32]);

impl fmt::Display for Txid {
    /// Display txid as 64-character hex string
    /// 
    /// Example: "a1b2c3d4e5f6...789" (64 hex chars)
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

// ============================================================================
// TRANSACTION INPUT
// ============================================================================

/// Transaction input — references a previous output by positional key.
///
/// Shisha Network uses positional UTXO storage (`rustmmrdb`): every output is keyed by
/// `(block_height, global_output_index_in_block)` rather than by txid.
/// This eliminates the O(window × txs) `build_txid_position_map` scan
/// (D2 in `rustmmrdb_phase4_plan_updated.md`) and aligns wire format with
/// the spend-storage key directly.
///
/// Coinbase transactions have an empty `inputs` vec — `is_coinbase()` returns
/// `self.inputs.is_empty()` unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    /// Block height at which the referenced output was created.
    pub prev_height: u32,

    /// Global output index within that block (across all transactions, 0-based).
    /// Matches `rustmmrdb::Outpoint::output_index` directly.
    pub prev_output_idx: u16,
    // Authorization moved to ShardBlockBody::witnesses[] (SegWit-style separation).
}

// ============================================================================
// TRANSACTION OUTPUT
// ============================================================================

/// Transaction output - creates a new unspent output
/// 
/// An output assigns value (in satoshis) to a recipient identified
/// by a script_pubkey. Once created, it becomes a UTXO until spent.
/// 
/// Bitcoin Model:
/// - Each output creates a new UTXO
/// - Value is in satoshis (1 BTC = 100,000,000 satoshis)
/// - Recipient identified by script_pubkey
/// 
/// Fields:
/// - value: Amount in satoshis
/// - script_pubkey: Recipient identification script
/// FV-3: Shisha Network transaction output — fixed 40 bytes, heap-free.
///
/// `recipient` is the x-only Schnorr public key (BIP-340 style) that controls
/// spending.  OP_RETURN / unspendable outputs use `[0u8; 32]` as a sentinel.
/// This matches `FlatOutput` exactly; they are kept as separate named types for
/// clarity at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount in satoshis.
    pub value: u64,
    /// x-only Schnorr public key (32 bytes, BIP-340 style).
    /// Use `[0u8; 32]` for OP_RETURN / unspendable outputs.
    pub recipient: [u8; 32],
}

// ============================================================================
// TRANSACTION
// ============================================================================

/// Bitcoin-style transaction with SegWit and Taproot support
/// 
/// A transaction consumes inputs (previous outputs) and creates
/// new outputs. It's the fundamental unit of value transfer in
/// the blockchain.
/// 
/// Transaction Types:
/// 1. Coinbase: No inputs, creates new coins (block reward)
/// 2. Regular: Spends existing outputs, creates new outputs
/// 3. SegWit: Includes witness data (signatures separated)
/// 
/// Bitcoin Compatibility:
/// - Version: Protocol version (usually 1 or 2)
/// - Inputs: List of outputs being spent
/// - Outputs: List of new outputs being created
/// - Locktime: When transaction becomes valid
/// - Witness: Optional SegWit data (BIP 141)
/// 
/// Validation:
/// - Structure validation: Context-free checks
/// - Input validation: Inputs must exist in UTXO set
/// - Value validation: Outputs ≤ inputs (no inflation)
/// - Signature validation: Proper authorization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version. There is exactly one: [`crate::common::validation::TX_VERSION`] (1),
    /// for coinbases and spends alike (owner decision Oct 17, 2026: the earlier version 2, which
    /// marked sighash-v2 spends, carried no meaning of its own and nothing branched on it).
    /// One `u8` representation everywhere: legacy struct, block body, txid and sighash.
    pub version: u8,

    /// Transaction inputs (outputs being spent)
    /// 
    /// Empty for coinbase transactions only.
    /// Each input must reference a valid UTXO (except coinbase).
    pub inputs: Vec<TxInput>,

    /// Transaction outputs (new UTXOs being created)
    /// 
    /// Must have at least one output.
    /// Each output creates a new UTXO until spent.
    pub outputs: Vec<TxOutput>,

    /// Lock time - when this transaction becomes valid
    /// 
    /// Interpretation:
    /// - 0: Valid immediately
    /// - < 500,000,000: Block height (valid at or after this block)
    /// - ≥ 500,000,000: Unix timestamp (valid at or after this time)
    /// 
    /// Used for time-locked transactions and payment channels.
    pub locktime: u32,

    /// CV-11 / TE-2: Expiration height — block at which this transaction expires.
    #[serde(default)]
    ///
    /// - 0: Never expires (immediate finality semantics).
    /// - N > 0: The transaction MUST NOT be included in any block at height >= N.
    ///   Valid inclusion window is `[locktime, expiration_height)`.
    ///
    /// The sighash commits to this field (design §20.5), so it cannot be stripped
    /// or modified post-signing without invalidating the signature.
    pub expiration_height: u32,

    /// Per-input Schnorr authorization for flat-body packing (`ShardBlockBody::witnesses[]`).
    ///
    /// Not included in the txid (re-signing never changes it); populated when
    /// building blocks via `ShardBlockBody::from_transactions`.
    #[serde(default)]
    pub witnesses: Vec<WitnessEntry>,

    /// Extension records other than the validity window (VF-3 Phase 1).
    ///
    /// The validity window is carried by `version`/`locktime`/`expiration_height`
    /// and is never stored here. Everything else in the transaction's extension
    /// slice (application records, the coinbase producer stamp, the miner
    /// extranonce) lives here in slice order, is part of the txid, and is
    /// re-emitted by `ShardBlockBody::from_transactions`.
    #[serde(default)]
    pub extensions: Vec<ExtensionRecord>,
}

// ============================================================================
// FLAT-VECTOR BLOCK BODY TYPES (FV-2 / FV-3)
// ============================================================================

/// Fixed-size 6-byte transaction input for the flat-vector block body.
///
/// Per-input Schnorr authorization is carried in `ShardBlockBody::witnesses[]`
/// (SegWit-style separation). `FlatInput` is therefore purely positional — 6 bytes, zero heap.
///
/// `TxInput` (with `script_sig`) is retired; `FlatInput` is the sole wire type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatInput {
    /// Block height at which the referenced output was created.
    pub prev_height: u32,
    /// Global output index within that block's flat outputs vector.
    pub prev_output_idx: u16,
}

impl FlatInput {
    /// Wire size of a serialised `FlatInput`.
    pub const SIZE: usize = 6;

    /// Serialise to 6 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..4].copy_from_slice(&self.prev_height.to_le_bytes());
        out[4..6].copy_from_slice(&self.prev_output_idx.to_le_bytes());
        out
    }

    /// Deserialise from 6 little-endian bytes.
    pub fn from_bytes(b: &[u8; 6]) -> Self {
        let prev_height     = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let prev_output_idx = u16::from_le_bytes(b[4..6].try_into().unwrap());
        Self { prev_height, prev_output_idx }
    }
}

/// Fixed-size 40-byte transaction output for the flat-vector block body.
///
/// `FlatOutput` aligns with `rustmmrdb::TxOutput` (already 40 bytes).
/// The `script_pubkey` field of the legacy `TxOutput` is replaced by a 32-byte
/// x-only Schnorr public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatOutput {
    /// Amount in satoshis.
    pub value: u64,
    /// x-only Schnorr public key (32 bytes, BIP-340 style).
    pub recipient: [u8; 32],
}

impl FlatOutput {
    /// Wire size of a serialised `FlatOutput`.
    pub const SIZE: usize = 40;

    /// Serialise to 40 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..8].copy_from_slice(&self.value.to_le_bytes());
        out[8..40].copy_from_slice(&self.recipient);
        out
    }

    /// Deserialise from 40 little-endian bytes.
    pub fn from_bytes(b: &[u8; 40]) -> Self {
        let value: u64 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&b[8..40]);
        Self { value, recipient }
    }
}

/// Witness entry — authorization data for one input (Schnorr signature + any aux data).
///
/// SegWit-style separation: witnesses are stored in `ShardBlockBody::witnesses[]`,
/// separate from `inputs[]`. Prunable after block validation.
/// One entry per input within a transaction (indexed by position within the tx's witness range).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEntry {
    pub witness_data: Vec<u8>,
}

impl WitnessEntry {
    /// Serialize as `length(4 LE) || data`.
    pub fn to_length_prefixed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.witness_data.len());
        out.extend_from_slice(&(self.witness_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.witness_data);
        out
    }

    /// Deserialize from `length(4 LE) || data`. Returns `(entry, bytes_consumed)`.
    pub fn from_length_prefixed_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 4 { return Err("witness entry too short for length"); }
        let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if data.len() < 4 + len { return Err("witness entry payload too short"); }
        Ok((Self { witness_data: data[4..4 + len].to_vec() }, 4 + len))
    }
}

/// Extension record header — typed, versioned metadata prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionHeader {
    /// Type registry: 0x0001–0x0FFF Consensus, 0x1000–0x1FFF Application, 0x2000+ Protocol/Experimental.
    pub extension_type: u16,
    pub version: u16,
    pub payload_length: u32,
}

/// Extension record — typed payload attached to a transaction.
///
/// Category 1 (Consensus, 0x0001–0x0FFF): must be validated by all nodes.
/// Category 2 (Application, 0x1000+): committed but not interpreted by consensus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRecord {
    pub header: ExtensionHeader,
    pub payload: Vec<u8>,
}

impl ExtensionRecord {
    pub const HEADER_SIZE: usize = 8; // 2 + 2 + 4

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.header.extension_type.to_le_bytes());
        out.extend_from_slice(&self.header.version.to_le_bytes());
        out.extend_from_slice(&self.header.payload_length.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Deserialize one record. Returns `(record, bytes_consumed)`.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < Self::HEADER_SIZE { return Err("extension header too short"); }
        let extension_type = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let version        = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let payload_length = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let end = Self::HEADER_SIZE + payload_length;
        if data.len() < end { return Err("extension payload too short"); }
        Ok((Self {
            header: ExtensionHeader { extension_type, version, payload_length: payload_length as u32 },
            payload: data[Self::HEADER_SIZE..end].to_vec(),
        }, end))
    }
}

/// Transaction boundary descriptor within a `ShardBlockBody`.
///
/// Replaces `TxRange`. Maps a logical transaction onto ranges in the five flat
/// vectors of `ShardBlockBody`.
///
/// **Coinbase marker (CB-1):** the first descriptor with `in_len == 0` is coinbase.
///
/// **Why there is no nonce field:** Unlike Ethereum, Shisha does not need a
/// per-transaction sender nonce to prevent replay attacks. Double-spending is
/// structurally impossible because every input references a unique positional
/// output `(prev_height: u32, prev_output_idx: u16)`; once that position is
/// marked spent in `PositionalUtxoDb` it can never be spent again. The descriptor
/// is therefore a pure positional-reference object with no identity payload.
///
/// The 8-byte `msg_id` field present in the Filament F2F wallet protocol
/// (`docs/plan/P2P_Phase10_Plan.md §4.1`) serves a completely different purpose:
/// it deduplicates wallet-layer messages (InvoiceRequest, PaymentProof) and is
/// never part of any on-chain structure.
///
/// Wire size: 28 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDescriptor {
    /// First output index in `ShardBlockBody::outputs`.
    pub out_start: u32,
    /// Number of outputs for this transaction.
    pub out_len: u32,
    /// First input index in `ShardBlockBody::inputs`.
    pub in_start: u32,
    /// Number of inputs (0 = coinbase).
    pub in_len: u32,
    /// First witness entry index in `ShardBlockBody::witnesses`.
    pub witness_start: u32,
    /// Number of witness entries (typically == in_len; 0 for coinbase).
    pub witness_len: u16,
    /// First extension record index in `ShardBlockBody::extensions`.
    pub extension_start: u32,
    /// Number of extension records (0 if none).
    pub extension_len: u16,
}

impl TransactionDescriptor {
    /// Wire size of a serialised `TransactionDescriptor`.
    pub const SIZE: usize = 28;

    pub fn is_coinbase(self) -> bool { self.in_len == 0 }

    /// Serialize to 28 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[0..4].copy_from_slice(&self.out_start.to_le_bytes());
        out[4..8].copy_from_slice(&self.out_len.to_le_bytes());
        out[8..12].copy_from_slice(&self.in_start.to_le_bytes());
        out[12..16].copy_from_slice(&self.in_len.to_le_bytes());
        out[16..20].copy_from_slice(&self.witness_start.to_le_bytes());
        out[20..22].copy_from_slice(&self.witness_len.to_le_bytes());
        out[22..26].copy_from_slice(&self.extension_start.to_le_bytes());
        out[26..28].copy_from_slice(&self.extension_len.to_le_bytes());
        out
    }

    /// Deserialize from 28 little-endian bytes.
    pub fn from_bytes(b: &[u8; 28]) -> Self {
        Self {
            out_start:       u32::from_le_bytes(b[0..4].try_into().unwrap()),
            out_len:         u32::from_le_bytes(b[4..8].try_into().unwrap()),
            in_start:        u32::from_le_bytes(b[8..12].try_into().unwrap()),
            in_len:          u32::from_le_bytes(b[12..16].try_into().unwrap()),
            witness_start:   u32::from_le_bytes(b[16..20].try_into().unwrap()),
            witness_len:     u16::from_le_bytes(b[20..22].try_into().unwrap()),
            extension_start: u32::from_le_bytes(b[22..26].try_into().unwrap()),
            extension_len:   u16::from_le_bytes(b[26..28].try_into().unwrap()),
        }
    }
}

/// Backward-compatibility alias. Use `TransactionDescriptor` in new code.
#[deprecated(since = "0.7.0", note = "use TransactionDescriptor")]
pub type TxRange = TransactionDescriptor;

impl Transaction {
    /// Create a new transaction
    /// 
    /// Creates an empty transaction with the specified version and locktime.
    /// Use add_input() and add_output() to populate it.
    /// 
    /// Parameters:
    /// - version: Protocol version number (usually 1 or 2)
    /// - locktime: Lock time (0 for immediate, or block height/timestamp)
    /// 
    /// Example:
    /// ```rust,ignore
    /// let tx = Transaction::new(1, 0); // Version 2, valid immediately
    /// ```
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

    /// Check if this is a coinbase transaction
    /// 
    /// Coinbase transactions:
    /// - Have no inputs (inputs.is_empty())
    /// - Create new coins from nothing (block reward)
    /// - Must be first transaction in every block
    /// - Only valid way to create new currency
    /// 
    /// Bitcoin consensus rule: Only coinbase transactions
    /// are allowed to have no inputs.
    /// 
    /// Returns: true if coinbase, false otherwise
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }
    
    /// Returns true when per-input Schnorr witnesses are attached.
    pub fn has_witnesses(&self) -> bool {
        !self.witnesses.is_empty()
    }

    /// Deprecated alias — use [`Self::has_witnesses`].
    #[deprecated(since = "0.7.0", note = "use has_witnesses(); legacy SegWit witness removed")]
    pub fn is_segwit(&self) -> bool {
        self.has_witnesses()
    }

    /// Add an input to this transaction
    /// 
    /// Appends an input to the inputs list.
    /// Each input spends a previous output.
    /// 
    /// Note: Remember to add corresponding witness data
    /// for SegWit inputs after adding all inputs.
    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    /// Add an output to this transaction
    /// 
    /// Appends an output to the outputs list.
    /// Each output creates a new UTXO.
    pub fn add_output(&mut self, output: TxOutput) {
        self.outputs.push(output);
    }
}

/*
===============================================================================
TRANSACTION TYPES MODULE - CORE DATA STRUCTURES
===============================================================================

PURPOSE
=======
Defines the fundamental types used throughout the transaction system.
These types represent the Bitcoin transaction model with full SegWit support.


DESIGN PRINCIPLES
=================

1. Bitcoin Compatibility:
   - Matches Bitcoin's transaction structure
   - Supports legacy and SegWit formats
   - Compatible with Bitcoin consensus rules

2. Type Safety:
   - Strong types (Txid is not just [u8; 32])
   - Clear ownership (Clone for copying)
   - Explicit nullability (Option<TxWitness>)

3. Serialization:
   - Serde support for JSON/binary formats
   - Custom serialization for Bitcoin wire format
   - Deterministic serialization

4. Extensibility:
   - Version field for future upgrades
   - Witness field for SegWit/Taproot
   - Script fields for new output types


TYPE RELATIONSHIPS
==================

Transaction
├── version: u32
├── inputs: Vec<TxInput>
│   ├── prev_height: u32       (block height of the referenced output)
│   ├── prev_output_idx: u16   (global output index within that block)
│   └── script_sig: Vec<u8>
├── outputs: Vec<TxOutput>
│   ├── value: u64
│   └── script_pubkey: Vec<u8>
├── locktime: u32
└── witness: Option<TxWitness>
    └── stacks: Vec<WitnessStack>
        └── items: Vec<Vec<u8>>


MEMORY LAYOUT
=============

Typical transaction sizes:
- TxInput: ~40 + script_sig.len() bytes
- TxOutput: ~8 + script_pubkey.len() bytes
- Transaction: ~20 + sum(inputs) + sum(outputs) bytes

Example (2 inputs, 2 outputs):
- Version: 4 bytes
- Inputs: 2 × 100 = 200 bytes (with signatures)
- Outputs: 2 × 40 = 80 bytes
- Locktime: 4 bytes
- Total: ~288 bytes (without witness)

SegWit witness adds:
- ~70 bytes per input for P2WPKH
- More for P2WSH or complex scripts


BITCOIN WIRE FORMAT
===================

Legacy Transaction:
┌─────────────┬─────────────┬─────────────┬─────────────┐
│   version   │   inputs    │   outputs   │  locktime   │
│   4 bytes   │  variable   │  variable   │   4 bytes   │
└─────────────┴─────────────┴─────────────┴─────────────┘

SegWit Transaction:
┌─────────┬────────┬──────┬────────┬─────────┬─────────┬──────────┐
│ version │ marker │ flag │ inputs │ outputs │ witness │ locktime │
│ 4 bytes │   00   │  01  │  var   │   var   │   var   │ 4 bytes  │
└─────────┴────────┴──────┴────────┴─────────┴─────────┴──────────┘


VALIDATION INVARIANTS
=====================

Transaction must satisfy:
1. Version ≥ 1
2. If not coinbase: inputs.len() > 0
3. outputs.len() > 0
4. No duplicate inputs
5. sum(outputs) ≤ sum(inputs) + block_reward (if coinbase)
6. If SegWit: witness.stacks.len() == inputs.len()


FUTURE EXTENSIONS
=================

This type system supports:
- Taproot (BIP 341): version field, witness structure
- SIGHASH types: Can be added to TxInput
- Sequence numbers: Can be added to TxInput
- RBF (Replace-By-Fee): Sequence number support
- CPFP (Child-Pays-For-Parent): Parent txid tracking


TESTING
=======

These types should be tested for:
- Serialization round-trips
- Display formatting
- Error display messages
- Clone/Copy behavior
- Hash/Eq implementation


===============================================================================
*/