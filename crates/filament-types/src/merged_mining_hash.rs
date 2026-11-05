//! Merged-mining tree node value (clean-room port; checked against the node by the shared vectors).
//!
//! A 32-byte node: bytes 0..30 are a hash prefix, byte 30 holds the subtree height (high 4 bits)
//! and the chain count's high 4 bits, byte 31 the chain count's low 8 bits. The header's
//! `merged_mining_root` is such a value, so a light client reads the number of active chains from
//! its last two bytes and never from any other field.

/// Largest chain count the 12-bit field holds.
pub const MAX_CHAIN_COUNT: u16 = 0x0FFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MergedMiningHash([u8; 32]);

impl MergedMiningHash {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Leaf of an active shard: the first 30 bytes of its header hash, height 0, count 1.
    pub fn from_active_leaf(shard_hash: &[u8; 32]) -> Self {
        let mut h = [0u8; 32];
        h[..30].copy_from_slice(&shard_hash[..30]);
        h[31] = 0x01;
        Self(h)
    }

    /// Leaf of an inactive shard: all zero.
    pub fn from_empty_leaf() -> Self {
        Self::ZERO
    }

    /// Parent of two children: `BLAKE3(left ‖ right)` with the last two bytes replaced by the
    /// height (max child height + 1, capped at 15) and the summed count (capped at 4095). Two
    /// all-zero children give an all-zero parent.
    pub fn combine(left: &Self, right: &Self) -> Self {
        if *left == Self::ZERO && *right == Self::ZERO {
            return Self::ZERO;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&left.0);
        hasher.update(&right.0);
        let mut h: [u8; 32] = hasher.finalize().into();
        let count = (left.chain_count() as u32 + right.chain_count() as u32).min(MAX_CHAIN_COUNT as u32) as u16;
        let height = (left.tree_height().max(right.tree_height()) + 1).min(15);
        h[30] = ((height & 0x0F) << 4) | ((count >> 8) as u8 & 0x0F);
        h[31] = (count & 0xFF) as u8;
        Self(h)
    }

    /// Build a value from a 30-byte prefix, a height (4 bits) and a count (12 bits); wider values
    /// are masked to their field.
    pub fn from_parts(prefix: &[u8; 30], tree_height: u8, chain_count: u16) -> Self {
        let mut h = [0u8; 32];
        h[..30].copy_from_slice(prefix);
        h[30] = ((tree_height & 0x0F) << 4) | ((chain_count >> 8) as u8 & 0x0F);
        h[31] = (chain_count & 0xFF) as u8;
        Self(h)
    }

    /// The same root with its packed count replaced (prefix and height kept).
    pub fn root_with_chain_count(root: [u8; 32], chain_count: u16) -> [u8; 32] {
        let mut r = root;
        r[30] = (r[30] & 0xF0) | ((chain_count >> 8) as u8 & 0x0F);
        r[31] = (chain_count & 0xFF) as u8;
        r
    }

    /// Chain count packed in a 32-byte merged-mining root.
    pub fn chain_count_of_root(root: &[u8; 32]) -> u16 {
        Self(*root).chain_count()
    }

    /// Tree height packed in a 32-byte merged-mining root.
    pub fn tree_height_of_root(root: &[u8; 32]) -> u8 {
        Self(*root).tree_height()
    }

    pub fn chain_count(&self) -> u16 {
        (((self.0[30] & 0x0F) as u16) << 8) | self.0[31] as u16
    }

    pub fn tree_height(&self) -> u8 {
        self.0[30] >> 4
    }

    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for MergedMiningHash {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<MergedMiningHash> for [u8; 32] {
    fn from(h: MergedMiningHash) -> [u8; 32] {
        h.0
    }
}
