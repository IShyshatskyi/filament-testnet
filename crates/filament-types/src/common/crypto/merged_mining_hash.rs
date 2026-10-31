// src/common/crypto/merged_mining_hash.rs
//
// MergedMiningHash — a 32-byte hash type that embeds chain-count and tree-height
// in its last 2 bytes, analogous to WeightedHash embedding rBits.
//
// Layout:
//   bytes  0–29  : 240-bit hash prefix (SHA256d[0..30] for leaves; BLAKE3[0..30] for nodes)
//   byte  30     : bits [7:4] = tree_height (4 bits, max 15)
//                  bits [3:0] = chain_count bits [11:8]
//   byte  31     : chain_count bits [7:0]
//
// Chain count is capped at 4095 (0xFFF) to fit in 12 bits.

use serde::{Deserialize, Serialize};

/// Maximum chain count that fits in the 12-bit embedded field.
pub const MAX_CHAIN_COUNT: u16 = 0x0FFF;

/// A 32-byte Merkle hash with chain-count and tree-height embedded in bytes 30–31.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedMiningHash([u8; 32]);

impl MergedMiningHash {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct a leaf hash for an **active** shard.
    ///
    /// `shard_hash` must be the SHA256d hash of the shard header (all 32 bytes).
    /// The first 30 bytes are used as the hash prefix; bytes 30–31 encode
    /// `tree_height = 0, chain_count = 1`.
    pub fn from_active_leaf(shard_hash: &[u8; 32]) -> Self {
        let mut h = [0u8; 32];
        h[..30].copy_from_slice(&shard_hash[..30]);
        h[30] = 0x00; // tree_height=0, chain_count bits [11:8]=0
        h[31] = 0x01; // chain_count bits [7:0] = 1
        Self(h)
    }

    /// Construct a leaf hash for an **inactive** shard.
    ///
    /// All 32 bytes are zero: hash prefix = 0, chain_count = 0, tree_height = 0.
    pub fn from_empty_leaf() -> Self {
        Self::ZERO
    }

    /// Combine two child `MergedMiningHash` values into a parent internal node.
    ///
    /// Hash rule: BLAKE3 of left.raw() ‖ right.raw(), with last 2 bytes overwritten
    /// by the accumulated `(tree_height, chain_count)` metadata.
    ///
    /// **Zero-propagation convention:** if both children are exactly [`Self::ZERO`]
    /// (an inactive leaf, or an ancestor that itself collapsed to `ZERO` under this
    /// same rule one level down), the parent is `ZERO` too — never a BLAKE3 hash of
    /// two zero inputs. This keeps "no active shard anywhere under this node" a
    /// single, cheap byte-equality check (`node == MergedMiningHash::ZERO`) at any
    /// level, all the way to the root, instead of only being decodable per-leaf via
    /// `chain_count() == 0`. Whenever at least one child carries real data, the
    /// parent is computed normally — a sibling update always still propagates up
    /// the path to the root, this only special-cases the specific
    /// both-children-empty combination.
    ///
    /// This changes `merged_mining_root` reconstruction for any proof whose sibling
    /// path touches a both-empty ancestor — a wire/consensus-relevant change to
    /// `verify_shard_id_and_mmn`'s root check, not an internal-only optimization
    /// (`beacon_header.merged_mining_root` is stored on-chain and re-derived via
    /// this exact function on every replay). Safe pre-mainnet with no durable chain
    /// history depending on the old rule; would need a hard-fork afterward.
    pub fn combine(left: &Self, right: &Self) -> Self {
        if *left == Self::ZERO && *right == Self::ZERO {
            return Self::ZERO;
        }

        let hash_prefix: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            h.update(&left.0);
            h.update(&right.0);
            h.finalize().into()
        };

        let chain_count = (left.chain_count() as u32 + right.chain_count() as u32)
            .min(MAX_CHAIN_COUNT as u32) as u16;
        let tree_height = left.tree_height().max(right.tree_height()) + 1;
        // cap tree_height at 15 (4 bits)
        let tree_height = tree_height.min(15);

        let mut h = hash_prefix;
        h[30] = ((tree_height & 0x0F) << 4) | (((chain_count >> 8) & 0x0F) as u8);
        h[31] = (chain_count & 0xFF) as u8;
        Self(h)
    }

    /// Number of active chains accumulated at this node.
    pub fn chain_count(&self) -> u16 {
        let hi = (self.0[30] & 0x0F) as u16;
        let lo = self.0[31] as u16;
        (hi << 8) | lo
    }

    /// Height of the subtree rooted at this node (0 = leaf).
    pub fn tree_height(&self) -> u8 {
        (self.0[30] >> 4) & 0x0F
    }

    /// Raw 32-byte representation.
    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<MergedMiningHash> for [u8; 32] {
    fn from(h: MergedMiningHash) -> [u8; 32] {
        h.0
    }
}

impl From<[u8; 32]> for MergedMiningHash {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmh_active_leaf_chain_count_1_height_0() {
        let h = MergedMiningHash::from_active_leaf(&[0xAB; 32]);
        assert_eq!(h.chain_count(), 1);
        assert_eq!(h.tree_height(), 0);
        // first 30 bytes match source
        assert_eq!(&h.raw()[..30], &[0xABu8; 30][..]);
    }

    #[test]
    fn mmh_empty_leaf_all_zeros() {
        let h = MergedMiningHash::from_empty_leaf();
        assert_eq!(h.chain_count(), 0);
        assert_eq!(h.tree_height(), 0);
        assert_eq!(h.raw(), &[0u8; 32]);
    }

    #[test]
    fn mmh_combine_two_active_leaves() {
        let l = MergedMiningHash::from_active_leaf(&[1u8; 32]);
        let r = MergedMiningHash::from_active_leaf(&[2u8; 32]);
        let p = MergedMiningHash::combine(&l, &r);
        assert_eq!(p.chain_count(), 2);
        assert_eq!(p.tree_height(), 1);
    }

    #[test]
    fn mmh_combine_monotone_count() {
        // active + inactive = 1
        let a = MergedMiningHash::from_active_leaf(&[1u8; 32]);
        let e = MergedMiningHash::from_empty_leaf();
        let p = MergedMiningHash::combine(&a, &e);
        assert_eq!(p.chain_count(), 1);
        assert_eq!(p.tree_height(), 1);
    }

    #[test]
    fn mmh_combine_tree_height_grows() {
        let l = MergedMiningHash::from_active_leaf(&[1u8; 32]);
        let r = MergedMiningHash::from_active_leaf(&[2u8; 32]);
        let depth1 = MergedMiningHash::combine(&l, &r);
        let depth2 = MergedMiningHash::combine(&depth1, &depth1);
        assert_eq!(depth2.tree_height(), 2);
        assert_eq!(depth2.chain_count(), 4);
    }

    #[test]
    fn mmh_combine_two_empty_leaves_is_exactly_zero() {
        let e1 = MergedMiningHash::from_empty_leaf();
        let e2 = MergedMiningHash::from_empty_leaf();
        let p = MergedMiningHash::combine(&e1, &e2);
        assert_eq!(p, MergedMiningHash::ZERO, "both-empty children must collapse to ZERO, not a BLAKE3 hash of two zero inputs");
        assert_eq!(p.chain_count(), 0);
        assert_eq!(p.tree_height(), 0);
    }

    #[test]
    fn mmh_zero_propagates_through_multiple_levels() {
        // Four inactive leaves, combined pairwise twice — every intermediate
        // and the final root must be exactly ZERO, not just chain_count==0.
        let e = MergedMiningHash::from_empty_leaf();
        let level1_left = MergedMiningHash::combine(&e, &e);
        let level1_right = MergedMiningHash::combine(&e, &e);
        assert_eq!(level1_left, MergedMiningHash::ZERO);
        assert_eq!(level1_right, MergedMiningHash::ZERO);
        let root = MergedMiningHash::combine(&level1_left, &level1_right);
        assert_eq!(root, MergedMiningHash::ZERO);
        assert_eq!(root.chain_count(), 0);
    }

    #[test]
    fn mmh_combine_one_zero_one_active_does_not_collapse() {
        // Only the exact both-zero case collapses -- a real sibling anywhere
        // in the pair still produces a real (non-ZERO) hash, and the parent
        // must not accidentally read as "everything under here is empty."
        let a = MergedMiningHash::from_active_leaf(&[7u8; 32]);
        let e = MergedMiningHash::from_empty_leaf();
        let p = MergedMiningHash::combine(&a, &e);
        assert_ne!(p, MergedMiningHash::ZERO);
        assert_eq!(p.chain_count(), 1);
    }

    #[test]
    fn mmh_chain_count_cap_at_4095() {
        // Fake a hash that already claims chain_count=4094
        let mut raw = [0u8; 32];
        // chain_count = 4094 = 0x0FFE
        raw[30] = (0 << 4) | 0x0F; // height=0, count hi nibble = 0xF
        raw[31] = 0xFE;             // count lo = 0xFE → 0x0FFE = 4094
        let near_max = MergedMiningHash::from(raw);
        assert_eq!(near_max.chain_count(), 4094);

        let one = MergedMiningHash::from_active_leaf(&[1u8; 32]);
        let combined = MergedMiningHash::combine(&near_max, &one);
        // 4094 + 1 = 4095, fits in 12 bits
        assert_eq!(combined.chain_count(), 4095);

        // One more — should clamp
        let combined2 = MergedMiningHash::combine(&combined, &one);
        assert_eq!(combined2.chain_count(), MAX_CHAIN_COUNT); // clamped at 4095
    }

    #[test]
    fn mmh_roundtrip_through_bytes() {
        let h = MergedMiningHash::from_active_leaf(&[7u8; 32]);
        let bytes: [u8; 32] = h.into();
        let h2 = MergedMiningHash::from(bytes);
        assert_eq!(h, h2);
    }

    #[test]
    fn mmh_combine_is_deterministic() {
        let a = MergedMiningHash::from_active_leaf(&[0x11; 32]);
        let b = MergedMiningHash::from_active_leaf(&[0x22; 32]);
        assert_eq!(MergedMiningHash::combine(&a, &b), MergedMiningHash::combine(&a, &b));
    }
}
