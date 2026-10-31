// src/common/crypto/merkle_hash.rs
//
// ============================================================================
// MERKLE TREE HASH PRIMITIVE
// ============================================================================
//
// PURPOSE
// -------
// Single authoritative location for the hash function used to build the
// transaction Merkle tree in both shard and beacon blocks.
//
// All modules that build or verify a Merkle tree MUST import from here.
// No block file should contain inline hashing calls for this purpose.
//
// LAYOUT — MerkleHash (32 bytes)
// --------------------------------
//
//   byte  0 .. 29  →  BLAKE3-240: first 30 bytes of BLAKE3 output
//   byte 30 .. 31  →  output_count : u16  big-endian
//                     For a leaf: number of outputs in that transaction.
//                     For an internal node: sum of output_counts of children.
//
// LEAF ALGORITHM
// --------------
//   input:  txid_240   — first 30 bytes of the transaction id
//           output_count — number of outputs in the transaction
//
//   hash_240   = BLAKE3_240( txid_240 || output_count_be16 )
//   MerkleHash = hash_240 || output_count_be16
//
// INTERNAL NODE ALGORITHM
// -----------------------
//   input:  left, right — two MerkleHash children
//
//   hash_240     = BLAKE3_240( left.raw() || right.raw() )
//   output_count = left.output_count().saturating_add(right.output_count())
//   MerkleHash   = hash_240 || output_count_be16
//
// EMPTY TREE
// ----------
//   MerkleHash::zero() = [0u8; 32]
//
// FUTURE: TRANSACTION MINING
// --------------------------
// The 16-bit tail (bytes 30..32) is intended as a proof-of-work commitment
// embedded in the txid itself.  Once transaction mining is enforced, a
// transaction will only be accepted if the last 2 bytes of its raw txid equal
// `output_count_be16`.  Miners will increment a nonce field until this
// condition is met.  The Merkle tree then carries a verifiable commitment to
// the output count without any extra bookkeeping.
//
// CHANGING THE ALGORITHM
// ----------------------
// 1. Update `merkle_leaf_hash` and `merkle_hash_pair` below.
// 2. Update the module header comment.
// 3. Update exact-value tests.
// 4. Bump the crate version — consensus-breaking change.
// Callers (shard_block.rs, beacon_block.rs) are unaffected.
//
// ============================================================================

/// Number of bytes in the hash portion of a MerkleHash.
pub const MERKLE_HASH_BYTES: usize = 30;

/// A 32-byte Merkle tree node value carrying a 240-bit structural hash and
/// a 16-bit cumulative output count.
///
/// # Layout
/// ```text
/// byte  0 .. 29  →  BLAKE3-240 structural hash
/// byte 30 .. 31  →  output_count  u16 big-endian
/// ```
///
/// # Invariant — internal node N with children L and R
/// - `N.hash_240()`      = `BLAKE3_240(L.raw() || R.raw())`
/// - `N.output_count()`  = `L.output_count().saturating_add(R.output_count())`
///
/// # Invariant — leaf for transaction T
/// - `N.hash_240()`      = `BLAKE3_240(txid_240 || output_count_be16)`
/// - `N.output_count()`  = number of outputs in T
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MerkleHash(pub [u8; 32]);

impl MerkleHash {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// All-zero sentinel, used for empty transaction lists.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create from a raw 32-byte array (e.g. when reading from storage).
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from explicit parts.
    pub fn from_parts(hash_240: [u8; MERKLE_HASH_BYTES], output_count: u16) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..MERKLE_HASH_BYTES].copy_from_slice(&hash_240);
        bytes[30..32].copy_from_slice(&output_count.to_be_bytes());
        Self(bytes)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// The 240-bit structural hash (bytes 0..30).
    pub fn hash_240(&self) -> [u8; MERKLE_HASH_BYTES] {
        let mut out = [0u8; MERKLE_HASH_BYTES];
        out.copy_from_slice(&self.0[..MERKLE_HASH_BYTES]);
        out
    }

    /// Cumulative output count (bytes 30..32, big-endian).
    ///
    /// For a leaf: the number of outputs in that transaction.
    /// For an internal node: the sum of output counts in the subtree.
    pub fn output_count(&self) -> u16 {
        u16::from_be_bytes([self.0[30], self.0[31]])
    }

    /// The raw 32-byte representation.
    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

// Allow cheap coercion to/from [u8; 32] for storage and header fields.
impl From<MerkleHash> for [u8; 32] {
    fn from(m: MerkleHash) -> [u8; 32] { m.0 }
}

impl From<[u8; 32]> for MerkleHash {
    fn from(b: [u8; 32]) -> MerkleHash { MerkleHash(b) }
}

impl std::fmt::Debug for MerkleHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleHash(hash={}, outputs={})",
            hex::encode(&self.0[..MERKLE_HASH_BYTES]),
            self.output_count())
    }
}

// ============================================================================
// Core hash primitives
// ============================================================================

/// Compute a MerkleHash leaf for a single transaction.
///
/// # Arguments
/// * `txid_240`     — first 30 bytes of the transaction id
/// * `output_count` — number of outputs in the transaction
///
/// # Algorithm
/// ```text
/// hash_240 = BLAKE3_240( txid_240 || output_count_be16 )
/// result   = hash_240 || output_count_be16
/// ```
pub fn merkle_leaf_hash(
    txid_240:     &[u8; MERKLE_HASH_BYTES],
    output_count: u16,
) -> MerkleHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(txid_240.as_slice());
    hasher.update(&output_count.to_be_bytes());

    let full = hasher.finalize();
    let mut hash_240 = [0u8; MERKLE_HASH_BYTES];
    hash_240.copy_from_slice(&full.as_bytes()[..MERKLE_HASH_BYTES]);

    MerkleHash::from_parts(hash_240, output_count)
}

/// Combine two MerkleHash nodes into their parent.
///
/// # Algorithm
/// ```text
/// hash_240     = BLAKE3_240( left.raw() || right.raw() )
/// output_count = left.output_count().saturating_add(right.output_count())
/// ```
///
/// # Properties
/// - Order-dependent: `merkle_hash_pair(L, R) ≠ merkle_hash_pair(R, L)`
/// - Deterministic: same inputs → same output
pub fn merkle_hash_pair(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left.raw().as_slice());
    hasher.update(right.raw().as_slice());

    let full = hasher.finalize();
    let mut hash_240 = [0u8; MERKLE_HASH_BYTES];
    hash_240.copy_from_slice(&full.as_bytes()[..MERKLE_HASH_BYTES]);

    let output_count = left.output_count().saturating_add(right.output_count());

    MerkleHash::from_parts(hash_240, output_count)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn txid_240(byte: u8) -> [u8; MERKLE_HASH_BYTES] {
        [byte; MERKLE_HASH_BYTES]
    }

    // ── Layout / accessors ──────────────────────────────────────────────────

    #[test]
    fn leaf_output_count_roundtrips() {
        let leaf = merkle_leaf_hash(&txid_240(0x01), 42);
        assert_eq!(leaf.output_count(), 42);
    }

    #[test]
    fn from_parts_and_accessors_consistent() {
        let hash_240 = [0xABu8; MERKLE_HASH_BYTES];
        let mh = MerkleHash::from_parts(hash_240, 100);
        assert_eq!(mh.hash_240(), hash_240);
        assert_eq!(mh.output_count(), 100);
    }

    // ── Leaf determinism & collision ────────────────────────────────────────

    #[test]
    fn leaf_is_deterministic() {
        let a = merkle_leaf_hash(&txid_240(0x42), 3);
        let b = merkle_leaf_hash(&txid_240(0x42), 3);
        assert_eq!(a, b);
    }

    #[test]
    fn different_txids_produce_different_leaves() {
        let a = merkle_leaf_hash(&txid_240(0x01), 1);
        let b = merkle_leaf_hash(&txid_240(0x02), 1);
        assert_ne!(a.hash_240(), b.hash_240());
    }

    #[test]
    fn different_output_counts_produce_different_hashes() {
        let a = merkle_leaf_hash(&txid_240(0x01), 1);
        let b = merkle_leaf_hash(&txid_240(0x01), 2);
        assert_ne!(a.hash_240(), b.hash_240());
    }

    // ── Internal node ───────────────────────────────────────────────────────

    #[test]
    fn pair_output_count_is_sum() {
        let l = merkle_leaf_hash(&txid_240(0x01), 3);
        let r = merkle_leaf_hash(&txid_240(0x02), 5);
        let parent = merkle_hash_pair(&l, &r);
        assert_eq!(parent.output_count(), 8);
    }

    #[test]
    fn pair_output_count_saturates() {
        let l = MerkleHash::from_parts([0u8; MERKLE_HASH_BYTES], u16::MAX);
        let r = MerkleHash::from_parts([1u8; MERKLE_HASH_BYTES], 1);
        let parent = merkle_hash_pair(&l, &r);
        assert_eq!(parent.output_count(), u16::MAX);
    }

    #[test]
    fn pair_is_deterministic() {
        let l = merkle_leaf_hash(&txid_240(0x01), 1);
        let r = merkle_leaf_hash(&txid_240(0x02), 2);
        assert_eq!(merkle_hash_pair(&l, &r), merkle_hash_pair(&l, &r));
    }

    #[test]
    fn pair_order_matters() {
        let l = merkle_leaf_hash(&txid_240(0x01), 1);
        let r = merkle_leaf_hash(&txid_240(0x02), 2);
        assert_ne!(merkle_hash_pair(&l, &r), merkle_hash_pair(&r, &l));
    }

    #[test]
    fn pair_hash_not_all_zeros() {
        let l = merkle_leaf_hash(&txid_240(0x00), 0);
        let r = merkle_leaf_hash(&txid_240(0x00), 0);
        let parent = merkle_hash_pair(&l, &r);
        assert_ne!(parent.hash_240(), [0u8; MERKLE_HASH_BYTES]);
    }

    // ── from/into [u8; 32] ──────────────────────────────────────────────────

    #[test]
    fn raw_roundtrip() {
        let leaf = merkle_leaf_hash(&txid_240(0xAB), 7);
        let recovered = MerkleHash::from_raw(*leaf.raw());
        assert_eq!(leaf, recovered);
    }

    #[test]
    fn from_into_array_roundtrip() {
        let leaf = merkle_leaf_hash(&txid_240(0xCD), 4);
        let arr: [u8; 32] = leaf.into();
        let back: MerkleHash = arr.into();
        assert_eq!(leaf, back);
    }
}
