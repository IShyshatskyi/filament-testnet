// filament-types/src/weighted_hash.rs
//
// WeightedHash: a 32-byte MMR node value that packs a 224-bit structural
// hash together with a 32-bit compact "rBits" cumulative-difficulty field
// (FlyClient-style — Bunz et al., 2020). This is pure, standard
// proof-verification math a light client must implement to check chain
// weight proofs; it carries no chain-construction/write logic.
//
// Layout: byte 0..28 = 224-bit hash, byte 28..32 = rBits (big-endian).

use serde::{Deserialize, Serialize};

pub const HASH_BYTES: usize = 28;
pub const WEIGHTED_HASH_SIZE: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct WeightedHash(pub [u8; WEIGHTED_HASH_SIZE]);

impl std::fmt::Debug for WeightedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WeightedHash({})", hex::encode(self.0))
    }
}

impl WeightedHash {
    pub const ZERO: Self = Self([0u8; WEIGHTED_HASH_SIZE]);

    pub fn zero() -> Self {
        Self::ZERO
    }

    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Genesis/anchor value: 224-bit hash from the anchor block hash, rBits = 0.
    pub fn from_anchor(anchor_hash: &[u8; 32]) -> Self {
        let mut wh = Self::zero();
        wh.0[..HASH_BYTES].copy_from_slice(&anchor_hash[..HASH_BYTES]);
        wh
    }

    /// Leaf from a block's PoW hash + header-native rBits (already the
    /// authoritative work field on real headers — no nBits conversion).
    pub fn from_leaf_rbits(block_hash: &[u8; 32], rbits: u32) -> Self {
        let mut hash_224 = [0u8; HASH_BYTES];
        hash_224.copy_from_slice(&block_hash[..HASH_BYTES]);
        Self::from_parts(hash_224, rbits)
    }

    pub fn from_parts(hash_224: [u8; HASH_BYTES], rbits: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..HASH_BYTES].copy_from_slice(&hash_224);
        bytes[HASH_BYTES..].copy_from_slice(&rbits.to_be_bytes());
        Self(bytes)
    }

    pub fn hash_bytes(&self) -> [u8; HASH_BYTES] {
        let mut h = [0u8; HASH_BYTES];
        h.copy_from_slice(&self.0[..HASH_BYTES]);
        h
    }

    pub fn rbits(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }

    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn has_weight(&self) -> bool {
        self.rbits() != 0
    }

    /// Decode rBits to an approximate u128 difficulty.
    pub fn cumulative_difficulty_approx(&self) -> u128 {
        rbits_to_u128_approx(self.rbits())
    }
}

impl std::ops::Deref for WeightedHash {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for WeightedHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

thread_local! {
    static BLAKE3_WEIGHTED: std::cell::RefCell<blake3::Hasher> =
        std::cell::RefCell::new(blake3::Hasher::new());
}

/// Combine two WeightedHash MMR node values into their parent.
///
/// Structural hash: BLAKE3(left.raw() || right.raw())[0..28].
/// rBits: sum of both children's decoded difficulty (doubled when equal, to
/// avoid the same quantization asymmetry the mantissa/exponent format would
/// otherwise introduce for equal siblings).
#[inline]
pub fn hash_pair_weighted(left: &WeightedHash, right: &WeightedHash) -> WeightedHash {
    let full_bytes = BLAKE3_WEIGHTED.with(|cell| {
        let mut h = cell.borrow_mut();
        h.reset();
        h.update(left.raw());
        h.update(right.raw());
        *h.finalize().as_bytes()
    });

    let mut hash_224 = [0u8; HASH_BYTES];
    hash_224.copy_from_slice(&full_bytes[..HASH_BYTES]);

    let l = left.rbits();
    let r = right.rbits();
    let combined_rbits = if l == r { rbits_double(l) } else { rbits_add(l, r) };

    WeightedHash::from_parts(hash_224, combined_rbits)
}

/// Bag a sequence of MMR peaks into a single root, left-to-right from the
/// anchor. The anchor itself carries zero weight.
pub fn bag_peaks_weighted(peaks: &[WeightedHash], anchor: WeightedHash) -> WeightedHash {
    if peaks.is_empty() {
        return anchor;
    }
    peaks.iter().fold(anchor, |acc, peak| hash_pair_weighted(&acc, peak))
}

// ── rBits compact-float arithmetic ──────────────────────────────────────────
// rBits packs a difficulty value as [size:u8 (top byte) | mantissa:u24],
// where `value ≈ mantissa * 256^(size - 3)`. Same shape as Bitcoin's nBits,
// but encoding difficulty (additive) rather than target (not additive).

fn rbits_to_mantissa_exp(rbits: u32) -> (u64, i32) {
    if rbits == 0 {
        return (0, 0);
    }
    let size = (rbits >> 24) as i32;
    let mantissa = (rbits & 0x00FF_FFFF) as u64;
    (mantissa, size - 3)
}

fn mantissa_exp_to_rbits(mut mantissa: u64, mut exp: i32) -> u32 {
    if mantissa == 0 {
        return 0;
    }
    while mantissa > 0x00FF_FFFF {
        mantissa >>= 8;
        exp += 1;
    }
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exp += 1;
    }
    let size = exp + 3;
    if size <= 0 {
        return 0;
    }
    if size > 32 {
        return 0xFF7F_FFFF;
    }
    ((size as u32) << 24) | (mantissa as u32 & 0x00FF_FFFF)
}

pub fn rbits_add(a: u32, b: u32) -> u32 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    let (ma, ea) = rbits_to_mantissa_exp(a);
    let (mb, eb) = rbits_to_mantissa_exp(b);
    let (sum_mantissa, exp) = if ea <= eb {
        let shift = (eb - ea) as u32;
        if shift >= 64 {
            return b;
        }
        let mb_shifted = mb.checked_shl(shift * 8).unwrap_or(u64::MAX);
        (ma.saturating_add(mb_shifted), ea)
    } else {
        let shift = (ea - eb) as u32;
        if shift >= 64 {
            return a;
        }
        let ma_shifted = ma.checked_shl(shift * 8).unwrap_or(u64::MAX);
        (mb.saturating_add(ma_shifted), eb)
    };
    mantissa_exp_to_rbits(sum_mantissa, exp)
}

pub fn rbits_double(r: u32) -> u32 {
    if r == 0 {
        return 0;
    }
    let (mantissa, exp) = rbits_to_mantissa_exp(r);
    mantissa_exp_to_rbits(mantissa << 1, exp)
}

/// Decode a compact rBits value to an approximate u128 difficulty.
pub fn rbits_to_u128_approx(rbits: u32) -> u128 {
    if rbits == 0 {
        return 0;
    }
    let (mantissa, exp) = rbits_to_mantissa_exp(rbits);
    if exp < 0 {
        let shift = (-exp) as u32;
        if shift >= 8 {
            return 0;
        }
        return mantissa as u128 >> (shift * 8);
    }
    let exp = exp as u32;
    if exp >= 16 {
        return u128::MAX;
    }
    (mantissa as u128).checked_shl(exp * 8).unwrap_or(u128::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_has_zero_weight() {
        let a = WeightedHash::from_anchor(&[0x11u8; 32]);
        assert_eq!(a.rbits(), 0);
        assert!(!a.has_weight());
    }

    #[test]
    fn hash_pair_weighted_sums_equal_rbits_via_double() {
        let a = WeightedHash::from_parts([1u8; 28], 0x0400_0001);
        let b = WeightedHash::from_parts([2u8; 28], 0x0400_0001);
        let parent = hash_pair_weighted(&a, &b);
        assert_eq!(parent.rbits(), rbits_double(0x0400_0001));
    }

    #[test]
    fn bag_peaks_empty_returns_anchor() {
        let anchor = WeightedHash::from_anchor(&[7u8; 32]);
        assert_eq!(bag_peaks_weighted(&[], anchor), anchor);
    }

    #[test]
    fn rbits_add_zero_identity() {
        assert_eq!(rbits_add(0, 12345), 12345);
        assert_eq!(rbits_add(12345, 0), 12345);
    }

    #[test]
    fn rbits_roundtrip_small_values() {
        // size=3 (exp=0), mantissa=1 → difficulty ≈ 1.
        let rbits = 0x0300_0001u32;
        assert_eq!(rbits_to_u128_approx(rbits), 1);
    }
}

#[cfg(test)]
mod xcheck {
    use super::*;

    #[test]
    fn xcheck_against_real_shisha_output() {
        let a = WeightedHash::from_leaf_rbits(&[0x11u8; 32], 0x0300_0040);
        let b = WeightedHash::from_leaf_rbits(&[0x22u8; 32], 0x0300_0040);
        let parent = hash_pair_weighted(&a, &b);
        assert_eq!(
            hex::encode(parent.raw()),
            "17b5bb86ac609726ec2fc9054c8183552ea06b04793113166eaa97e303000080"
        );

        let anchor = WeightedHash::from_anchor(&[0xAAu8; 32]);
        let root = bag_peaks_weighted(&[a, b, parent], anchor);
        assert_eq!(
            hex::encode(root.raw()),
            "b83ea30520689dfaecf6417bd0f36ecf03995e135cbbe165aeb02b0a03000100"
        );
        assert_eq!(root.cumulative_difficulty_approx(), 256);
    }
}
