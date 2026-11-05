//! Shard block body: transaction leaves, the position-binding merkle root and output inclusion
//! proofs (clean-room port; checked against the node by the shared vectors).
//!
//! A body is five flat vectors plus one descriptor per transaction that says which slice of each
//! vector the transaction owns. The header commits to `tx_merkle_root`, a merkle tree over one leaf
//! per transaction. A light client proves that an output is in a block by receiving the owning
//! transaction's slices, recomputing its leaf, and walking a path to that root.

use crate::transaction_impl::{ExtensionRecord, FlatInput, FlatOutput, WitnessEntry};
use serde::{Deserialize, Serialize};

/// Consensus extension type of the shard coinbase "rule amount" marker.
pub const CONSENSUS_EXT_RULE_AMOUNT: u16 = 0x0003;

/// True when one transaction's extension slice contains the rule-amount marker.
pub fn has_rule_amount_marker(extensions: &[ExtensionRecord]) -> bool {
    extensions.iter().any(|e| e.header.extension_type == CONSENSUS_EXT_RULE_AMOUNT)
}

/// Which slice of each flat vector one transaction owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDescriptor {
    pub out_start: u32,
    pub out_len: u32,
    pub in_start: u32,
    pub in_len: u32,
    pub witness_start: u32,
    pub witness_len: u16,
    pub extension_start: u32,
    pub extension_len: u16,
}

impl TransactionDescriptor {
    pub const SIZE: usize = 28;

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
}

/// Leaf of one transaction. A coinbase with no inputs that carries the rule-amount marker is hashed
/// with output 0's value and recipient as zero: the reward rule fixes the amount and the beacon
/// coinbase record fixes the recipient, so neither is part of the commitment.
pub fn tx_leaf_hash_from_parts(
    d: &TransactionDescriptor,
    inputs: &[FlatInput],
    outputs: &[FlatOutput],
    witnesses: &[WitnessEntry],
    extensions: &[ExtensionRecord],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for inp in inputs {
        h.update(&inp.to_bytes());
    }
    let value_excluded = inputs.is_empty() && has_rule_amount_marker(extensions);
    for (i, out) in outputs.iter().enumerate() {
        if value_excluded && i == 0 {
            h.update(&FlatOutput { value: 0, recipient: [0u8; 32] }.to_bytes());
        } else {
            h.update(&out.to_bytes());
        }
    }
    for w in witnesses {
        h.update(&(w.witness_data.len() as u32).to_le_bytes());
        h.update(&w.witness_data);
    }
    for e in extensions {
        h.update(&e.header.extension_type.to_le_bytes());
        h.update(&e.header.version.to_le_bytes());
        h.update(&(e.payload.len() as u32).to_le_bytes());
        h.update(&e.payload);
    }
    h.update(&d.to_bytes());
    h.finalize().into()
}

/// Tree node of the leaf at position `idx`: `BLAKE3(idx_le32 ‖ leaf)`.
pub fn tx_merkle_node(idx: u32, tx_leaf_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&idx.to_le_bytes());
    h.update(tx_leaf_hash);
    h.finalize().into()
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Check a merkle path from the leaf at `idx` to `root`.
pub fn verify_tx_merkle_path(idx: u32, tx_leaf_hash: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut cur = tx_merkle_node(idx, tx_leaf_hash);
    let mut pos = idx;
    for sib in path {
        cur = if pos & 1 == 0 { parent(&cur, sib) } else { parent(sib, &cur) };
        pos >>= 1;
    }
    &cur == root
}

/// The five flat vectors and the descriptors of a shard block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardBlockBody {
    pub outputs: Vec<FlatOutput>,
    pub inputs: Vec<FlatInput>,
    pub witnesses: Vec<WitnessEntry>,
    pub extensions: Vec<ExtensionRecord>,
    pub descriptors: Vec<TransactionDescriptor>,
}

impl ShardBlockBody {
    /// Leaf of transaction `idx`. A slice that lies outside its vector hashes as if absent.
    pub fn tx_leaf_hash(&self, idx: usize) -> Option<[u8; 32]> {
        let d = self.descriptors.get(idx)?;
        let slice = |start: u32, len: usize| (start as usize, (start as usize).checked_add(len));
        let range = |(a, b): (usize, Option<usize>)| b.map(|b| a..b);
        let ins = range(slice(d.in_start, d.in_len as usize)).and_then(|r| self.inputs.get(r)).unwrap_or(&[]);
        let outs = range(slice(d.out_start, d.out_len as usize)).and_then(|r| self.outputs.get(r)).unwrap_or(&[]);
        let wits = range(slice(d.witness_start, d.witness_len as usize)).and_then(|r| self.witnesses.get(r)).unwrap_or(&[]);
        let exts = range(slice(d.extension_start, d.extension_len as usize)).and_then(|r| self.extensions.get(r)).unwrap_or(&[]);
        Some(tx_leaf_hash_from_parts(d, ins, outs, wits, exts))
    }

    /// The header's `tx_merkle_root`: zero for an empty body, else the tree over all tx leaves.
    pub fn calculate_tx_merkle_root(&self) -> [u8; 32] {
        let mut nodes = self.leaf_nodes();
        if nodes.is_empty() {
            return [0u8; 32];
        }
        while nodes.len() > 1 {
            nodes = Self::next_level(&nodes);
        }
        nodes[0]
    }

    fn leaf_nodes(&self) -> Vec<[u8; 32]> {
        (0..self.descriptors.len())
            .map(|i| tx_merkle_node(i as u32, &self.tx_leaf_hash(i).unwrap_or([0u8; 32])))
            .collect()
    }

    fn next_level(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
        (0..nodes.len())
            .step_by(2)
            .map(|i| {
                let left = nodes[i];
                let right = if i + 1 < nodes.len() { nodes[i + 1] } else { left };
                parent(&left, &right)
            })
            .collect()
    }

    /// Sibling path of transaction `idx` (an unpaired node is its own sibling).
    pub fn tx_merkle_path(&self, idx: usize) -> Option<Vec<[u8; 32]>> {
        if idx >= self.descriptors.len() {
            return None;
        }
        let mut nodes = self.leaf_nodes();
        let mut pos = idx;
        let mut path = Vec::new();
        while nodes.len() > 1 {
            path.push(if pos ^ 1 < nodes.len() { nodes[pos ^ 1] } else { nodes[pos] });
            nodes = Self::next_level(&nodes);
            pos >>= 1;
        }
        Some(path)
    }

    /// Proof that output `output_idx` of this block exists, carried as its transaction's slices.
    pub fn tx_inclusion_proof(&self, height: u32, output_idx: u32) -> Option<TxInclusionProof> {
        let idx = self.descriptors.iter().position(|d| {
            output_idx >= d.out_start && (output_idx as u64) < d.out_start as u64 + d.out_len as u64
        })?;
        let d = self.descriptors[idx];
        let take = |start: u32, len: usize| (start as usize)..(start as usize + len);
        Some(TxInclusionProof {
            height,
            output_idx,
            tx_idx: idx as u32,
            descriptor: d,
            inputs: self.inputs.get(take(d.in_start, d.in_len as usize))?.to_vec(),
            outputs: self.outputs.get(take(d.out_start, d.out_len as usize))?.to_vec(),
            witnesses: self.witnesses.get(take(d.witness_start, d.witness_len as usize))?.to_vec(),
            extensions: self.extensions.get(take(d.extension_start, d.extension_len as usize))?.to_vec(),
            path: self.tx_merkle_path(idx)?,
        })
    }
}

/// An output of a shard block, with everything needed to check it against the block's `tx_merkle_root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInclusionProof {
    pub height: u32,
    pub output_idx: u32,
    pub tx_idx: u32,
    pub descriptor: TransactionDescriptor,
    pub inputs: Vec<FlatInput>,
    pub outputs: Vec<FlatOutput>,
    pub witnesses: Vec<WitnessEntry>,
    pub extensions: Vec<ExtensionRecord>,
    pub path: Vec<[u8; 32]>,
}

impl TxInclusionProof {
    /// The proven output.
    pub fn output(&self) -> Option<&FlatOutput> {
        let d = &self.descriptor;
        if self.output_idx < d.out_start {
            return None;
        }
        self.outputs.get((self.output_idx - d.out_start) as usize)
    }

    /// False for output 0 of a rule-amount coinbase: its value and recipient are not committed
    /// by the leaf, so a proof cannot vouch for them.
    pub fn value_is_committed(&self) -> bool {
        let first_output_of_marked_coinbase = self.inputs.is_empty()
            && has_rule_amount_marker(&self.extensions)
            && self.output_idx == self.descriptor.out_start;
        !first_output_of_marked_coinbase
    }

    /// Check the proof against a header's `tx_merkle_root`.
    pub fn verify(&self, tx_merkle_root: &[u8; 32]) -> bool {
        let d = &self.descriptor;
        if self.inputs.len() != d.in_len as usize
            || self.outputs.len() != d.out_len as usize
            || self.witnesses.len() != d.witness_len as usize
            || self.extensions.len() != d.extension_len as usize
            || self.output().is_none()
        {
            return false;
        }
        let leaf = tx_leaf_hash_from_parts(d, &self.inputs, &self.outputs, &self.witnesses, &self.extensions);
        verify_tx_merkle_path(self.tx_idx, &leaf, &self.path, tx_merkle_root)
    }
}
