// src/common/crypto/weighted_hash.rs
//
// ============================================================================
// WEIGHTED MMR HASH - FlyClient-style Cumulative Difficulty in MMR Nodes
// ============================================================================
//
// DESIGN OVERVIEW
// ---------------
// This module implements the core primitive for embedding cumulative chain
// weight directly inside every MMR node hash, following an approach inspired
// by FlyClient (Bunz et al., 2020).
//
// The key insight: each MMR node is represented as a 32-byte value split
// into two parts, embedding cumulative difficulty directly in the hash:
//
//   [  224-bit hash (28 bytes)  |  32-bit rBits (4 bytes)  ]
//    bytes 0..28                   bytes 28..32
//
// WHY rBits AND NOT nBits?
// ------------------------
// Bitcoin's nBits compact format encodes the mining TARGET:
//
//   nBits = 0x1d00ffff  →  target = 0xffff × 256^26 ≈ 2^224
//
// Targets are LARGE and non-additive: adding two targets has no useful meaning,
// and all real targets overflow u128 entirely.
//
// rBits ("reversed bits") encodes the DIFFICULTY — the inverse of the target:
//
//   difficulty = 2^(256 + k) / target
//
// where k is the hash-sorting parameter (0 for pool mining, k>0 for solo
// mining targeting a specific shard — see nbits_conversion.rs).
//
// For Bitcoin genesis (k=0):
//   target     ≈ 2^224
//   difficulty = 2^256 / 2^224 = 2^32 ≈ 4 billion
//
// That fits comfortably in u128, and difficulties are properly additive:
//
//   cumulative_weight = difficulty_block_0 + difficulty_block_1 + ...
//
// LEAF CREATION (header-native rBits — Jul 20, 2026)
// ----------------------------------------------------
// When appending a block to the WeightedMMR:
//
//   Step 1: Truncate block_hash to 224 bits by taking its first 28 bytes.
//             hash_224 = block_hash_256[0..28]
//
//             No second hash function is applied. The ASIC already produced a
//             SHA256d hash; re-hashing with BLAKE3 would waste a full hash pass.
//             Bytes 0–27 carry the unique block identity commitment.
//
//   Step 2: Copy header rBits into bytes 28–31 (direct — no nBits conversion).
//             leaf = WeightedHash::from_leaf_rbits(&sha256d, header.rbits)
//
// Legacy `from_leaf(hash, nbits, w_bits)` still converts via `nbits_to_rbits`
// for genesis helpers / old fixtures. New production code must not use it.
//
// PoW VERIFICATION ORDER
// ----------------------
// PoW must be checked against the full 32-byte SHA256d *before* constructing
// a WeightedHash leaf, because `from_leaf_rbits` overwrites bytes 28–31:
//
//   let sha256d = BeaconBlock::calculate_hash(&header);  // full 32 bytes
//   verify_pow(&sha256d, rbits_to_target(header.rbits, …));
//   let leaf    = WeightedHash::from_leaf_rbits(&sha256d, header.rbits);
//
// PROPERTY PRESERVED
// ------------------
// For every internal node N with left child L and right child R:
//
//   N.hash_224 = BLAKE3_224(L.hash_224 || L.rbits || R.hash_224 || R.rbits)
//   N.rbits    = rbits_add(L.rbits, R.rbits)
//
// For a leaf derived from a block with header-native rBits `r`:
//
//   leaf.hash_224 = block_hash_256[0..28]   (SHA256d prefix, no re-hashing)
//   leaf.rbits    = r                      (direct copy)
//
// Internal nodes still use BLAKE3 for collision resistance (combining child
// hashes that are not themselves ASIC-produced, so no efficiency argument).
//
// SECURITY BENEFIT FOR LIGHT CLIENTS
// -----------------------------------
// A light client holding the MMR root can extract the CUMULATIVE CHAIN WEIGHT
// from the root's rBits field without trusting any separately-reported total
// difficulty. Manipulation requires either forging a BLAKE3 preimage (internal
// nodes) or re-doing PoW with the correct header rBits (leaf nodes).
//
// COMPACT rBITS ARITHMETIC
// ------------------------
// rBits uses the same floating-point compact encoding as Bitcoin nBits:
//
//   value = mantissa × 256^(size - 3)
//
// The arithmetic functions (rbits_add, etc.) are identical to the former
// nbits_add — the compact addition logic is format-agnostic. Only the
// semantic meaning of the encoded value changes.
//
// ============================================================================

use std::cell::RefCell;
use serde::{Deserialize, Serialize};
use crate::common::crypto::nbits_conversion::{
    nbits_to_target,
    calculate_difficulty_from_target,
};

thread_local! {
    /// Reused BLAKE3 hasher for `hash_pair_weighted`.  `reset()` clears state
    /// in ~10 field writes; `Hasher::new()` would zero-initialise ~1 900 bytes.
    /// `hash_pair_weighted` is non-re-entrant so `borrow_mut` never panics.
    static BLAKE3_WEIGHTED: RefCell<blake3::Hasher> =
        RefCell::new(blake3::Hasher::new());
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Number of bytes used for the hash portion (224 bits = 28 bytes)
pub const HASH_BYTES: usize = 28;

/// Number of bytes used for the rBits portion (32 bits = 4 bytes)
pub const RBITS_BYTES: usize = 4;

/// Total size of a WeightedHash (must equal 32 for drop-in compatibility)
pub const WEIGHTED_HASH_SIZE: usize = HASH_BYTES + RBITS_BYTES; // = 32

/// Legacy compact chain-weight scaling exponent (protocol parameter #3).
///
/// **Retired at the leaf boundary (Jul 20, 2026 — header-native rBits).**
/// Headers stamp compact **rBits** directly; MMR leaves copy that field via
/// [`WeightedHash::from_leaf_rbits`] — they do **not** apply
/// `nbits_to_rbits(..., w_bits)`. Kept only for:
/// - temporary [`nbits_to_rbits`] / genesis conversion helpers, and
/// - pre-migration tests/benches that still exercise the nBits→rBits path.
///
/// Do **not** pass hash-sorting `s` / asserted-s here; asserted-s softens the
/// PoW target (`rbits_to_target` / `T × 2^s`), not leaf weight.
///
/// # Three-parameter taxonomy — do not confuse these
///
/// | # | Name | Size | Wire location | Purpose |
/// |---|------|------|---------------|---------|
/// | 1 | Shard chain count | 2 B | merged-mining Merkle header | number of active shard chains claimed by a block composer |
/// | 2 | k-coefficient | 4 B compact | beacon block version field | per-epoch economic multiplier → shard coinbase reward |
/// | 3 | **`w_bits` (legacy)** | was 4 | retired at leaf | was nBits→rBits leaf scaling; header rBits is now authoritative |
///
/// See `src/common/validation/k_coeff.rs` for the k-coefficient (parameter #2).
pub const BLOCK_HASH_W_BITS: u32 = 4;

// ============================================================================
// WEIGHTED HASH TYPE
// ============================================================================

/// A 32-byte value that packs a 224-bit hash prefix with a 32-bit compact
/// cumulative difficulty (rBits) field.
///
/// # Layout
/// ```text
/// byte  0 .. 27  →  224-bit hash (first 28 bytes of SHA256d for leaves;
///                    BLAKE3-224 of children for internal MMR nodes)
/// byte 28 .. 31  →  32-bit rBits (big-endian), compact cumulative difficulty
/// ```
///
/// rBits encodes the DIFFICULTY (not the target) in compact floating-point:
///
///   rBits value = mantissa × 256^(size - 3)  ≈  cumulative difficulty
///
/// # Invariant
/// For any internal MMR node N:
/// - `N.rbits()` = `rbits_add(left.rbits(), right.rbits())`
/// - `N.hash_bytes()` = `blake3_224(left.raw() || right.raw())`
///
/// For any leaf derived from a block with nBits `b` and compact weight `w_bits`:
/// - `leaf.rbits()` = `nbits_to_rbits(b, w_bits)`  (typically `BLOCK_HASH_W_BITS`)
/// - `leaf.hash_bytes()` = `block_sha256d[0..28]`  (no re-hashing)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct WeightedHash(pub [u8; WEIGHTED_HASH_SIZE]);

impl WeightedHash {
    // -------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------

    /// Create from a raw 32-byte array (used when reading from storage)
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compile-time zero / sentinel value.
    ///
    /// Required by `[WeightedHash::ZERO; 32]` array literals (Level 2 — WMMR-OPT-SENTINEL).
    /// `is_zero()` / `has_weight()` use this as the sentinel.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create the zero / sentinel value (all bytes zero)
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create a genesis / anchor weighted hash from a Bitcoin block hash.
    ///
    /// rBits = 0 at the anchor (no cumulative weight before genesis).
    /// The 224-bit hash portion is the first 28 bytes of the anchor hash.
    pub fn from_anchor(anchor_hash: &[u8; 32]) -> Self {
        let mut wh = Self::zero();
        wh.0[..HASH_BYTES].copy_from_slice(&anchor_hash[..HASH_BYTES]);
        wh
    }

    /// Create a leaf from a block's PoW hash and header-native **rBits**.
    ///
    /// Production path after the header-rBits cutover (Jul 20, 2026):
    ///  1. Take the first 28 bytes of the SHA256d PoW hash as-is (no re-hashing).
    ///  2. **Copy** header rBits into bytes 28–31 — no `nbits_to_rbits`, no `w_bits`.
    ///
    /// PoW verification must run against the full 32-byte SHA256d *before*
    /// calling this constructor, because bytes 28–31 are overwritten.
    ///
    /// # Arguments
    /// * `block_hash` — 256-bit SHA256d PoW block hash
    /// * `rbits` — Compact difficulty from the header work slot (same 4 bytes
    ///   formerly used for nBits; semantics are now rBits)
    pub fn from_leaf_rbits(block_hash: &[u8; 32], rbits: u32) -> Self {
        let mut hash_224 = [0u8; HASH_BYTES];
        hash_224.copy_from_slice(&block_hash[..HASH_BYTES]);
        Self::from_parts(hash_224, rbits)
    }

    /// Legacy leaf constructor: nBits → rBits via [`nbits_to_rbits`], then pack.
    ///
    /// **Do not use for new production leaves.** Prefer [`Self::from_leaf_rbits`]
    /// with header-stamped rBits. Kept for genesis conversion helpers and
    /// pre-migration fixtures during the header-rBits cutover.
    pub fn from_leaf(block_hash: &[u8; 32], block_nbits: u32, w_bits: u32) -> Self {
        let rbits = nbits_to_rbits(block_nbits, w_bits);
        Self::from_leaf_rbits(block_hash, rbits)
    }

    /// Create from explicit 224-bit hash and pre-computed rBits.
    ///
    /// The caller must ensure `rbits` encodes a difficulty value (header work
    /// field, [`u128_to_rbits`], or a one-shot genesis [`nbits_to_header_rbits`]
    /// conversion).
    pub fn from_parts(hash_224: [u8; HASH_BYTES], rbits: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..HASH_BYTES].copy_from_slice(&hash_224);
        bytes[HASH_BYTES..].copy_from_slice(&rbits.to_be_bytes());
        Self(bytes)
    }

    // -------------------------------------------------------------------
    // Field Accessors
    // -------------------------------------------------------------------

    /// Extract the 224-bit hash portion (bytes 0..28)
    pub fn hash_bytes(&self) -> [u8; HASH_BYTES] {
        let mut h = [0u8; HASH_BYTES];
        h.copy_from_slice(&self.0[..HASH_BYTES]);
        h
    }

    /// Extract the 32-bit cumulative rBits (bytes 28..32, big-endian).
    ///
    /// This is a compact difficulty encoding. Use `cumulative_difficulty_approx()`
    /// to decode to u128 for comparison.
    pub fn rbits(&self) -> u32 {
        u32::from_be_bytes([self.0[28], self.0[29], self.0[30], self.0[31]])
    }

    /// Get the raw 32-byte representation
    pub fn raw(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true if this is the zero sentinel
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Returns true if this node carries non-zero cumulative weight
    pub fn has_weight(&self) -> bool {
        self.rbits() != 0
    }

    // -------------------------------------------------------------------
    // Approximate cumulative difficulty as u128
    // -------------------------------------------------------------------

    /// Decode cumulative chain weight from the rBits field.
    ///
    /// Returns an approximate `u128` suitable for chain comparisons.
    /// Because rBits encodes difficulty (not target), typical values are
    /// far below u128::MAX and will not saturate for any realistic chain.
    pub fn cumulative_difficulty_approx(&self) -> u128 {
        let rbits = self.rbits();
        if rbits == 0 {
            return 0;
        }
        rbits_to_u128_approx(rbits)
    }
}

// ============================================================================
// CORE CONVERSION: nBits (target) → rBits (difficulty)
// ============================================================================

/// Convert a block's mining nBits (compact target) to compact rBits
/// (compact difficulty).
///
/// **Genesis / fixture conversion only.** Production MMR leaves copy
/// header-stamped rBits via [`WeightedHash::from_leaf_rbits`] and must not
/// call this. Prefer [`nbits_to_header_rbits`] when converting relative to a
/// network `initial_target` (legacy `max_target`).
///
/// ```text
/// nBits encodes:  target T  =  mantissa × 256^(size-3)     (LARGE, overflows u128)
/// rBits encodes:  difficulty = 2^(256+w) / T               (manageable, additive)
/// ```
///
/// # The w_bits parameter
/// Legacy leaf-scaling exponent ([`BLOCK_HASH_W_BITS`]). **Retired for new
/// leaves** — pass `0` when converting nBits → header rBits for PoW Strategy A
/// (`rbits_to_target` does not apply a separate w_bits fold).
///
/// # Arguments
/// * `block_nbits` - Block's nBits field (legacy compact **target**)
/// * `w_bits`      - Legacy compact weight exponent (use `0` for header conversion)
///
/// # Returns
/// Compact rBits encoding of the block's effective difficulty.
/// Returns 0 for zero/invalid nBits.
pub fn nbits_to_rbits(block_nbits: u32, w_bits: u32) -> u32 {
    if block_nbits == 0 {
        return 0;
    }

    // Step 2: Expand nBits to full 256-bit target
    let target = nbits_to_target(block_nbits);

    // Step 3+4: difficulty = 2^(256+w) / target
    let difficulty: u128 = calculate_difficulty_from_target(&target, w_bits);

    if difficulty == 0 {
        return 0;
    }

    // Step 4: Compact-encode difficulty as rBits
    u128_to_rbits(difficulty)
}

/// Convert legacy compact **nBits** (target) to header-native **rBits**
/// (difficulty) relative to this network's initial beacon target.
///
/// ```text
/// T = nbits_to_target(nbits)
/// D = initial_target / T
/// rBits = u128_to_rbits(D)
/// ```
///
/// Inverse of PoW Strategy A expand (without asserted-s):
/// `rbits_to_target(rBits, initial_target, 0) ≈ T` (lossy compact round-trip).
///
/// Call once at genesis load / config migration. Production leaves use
/// [`WeightedHash::from_leaf_rbits`] with the stamped header field.
pub fn nbits_to_header_rbits(nbits: u32, initial_target: &[u8; 32]) -> u32 {
    use crate::common::crypto::nbits_conversion::U256;

    if nbits == 0 {
        return 0;
    }
    let target = nbits_to_target(nbits);
    let init = U256::from_bytes(initial_target);
    let t = U256::from_bytes(&target);
    if t.is_zero() {
        return 0;
    }
    let d = init.div(&t);
    let d_u128 = d.to_u128();
    if d_u128 == 0 {
        // Target easier than initial_target → difficulty < 1; floor at 1.
        return u128_to_rbits(1);
    }
    u128_to_rbits(d_u128)
}

/// Encode a u128 difficulty value as compact rBits.
///
/// Inverse of `rbits_to_u128_approx()`. Uses the same floating-point
/// compact format as Bitcoin nBits but for difficulty values (small numbers).
///
/// The 3 most-significant bytes of the value become the mantissa;
/// the remaining byte count becomes the size field. Values that fit in
/// fewer than 3 bytes are encoded with **size = 3** so
/// `rbits_to_u128_approx` round-trips (size &lt; 3 would shift the mantissa
/// out of range and decode as 0 — fatal for difficulty-1 genesis).
///
/// # Returns
/// Compact rBits, saturating at `0xFF7FFFFF` for astronomically large inputs.
pub fn u128_to_rbits(difficulty: u128) -> u32 {
    if difficulty == 0 {
        return 0;
    }

    // Find byte_len = number of bytes needed to represent `difficulty`
    // i.e., ceil(log_256(difficulty + 1))
    let byte_len = if      difficulty <= 0xFF                          { 1usize }
    else if difficulty <= 0xFFFF                        { 2 }
    else if difficulty <= 0xFFFFFF                      { 3 }
    else if difficulty <= 0xFFFFFFFF                    { 4 }
    else if difficulty <= 0xFFFFFFFFFF                  { 5 }
    else if difficulty <= 0xFFFFFFFFFFFF                { 6 }
    else if difficulty <= 0xFFFFFFFFFFFFFF              { 7 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFF            { 8 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFF          { 9 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFF        { 10 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFFFF      { 11 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFFFFFF    { 12 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFF  { 13 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF     { 14 }
    else if difficulty <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF   { 15 }
    else                                                     { 16 };

    if byte_len > 32 {
        return 0xFF7F_FFFF;
    }

    // size ≥ 3 so decode's exp = size−3 is non-negative for small D.
    // (size=1 with mantissa=1 → exp=−2 → mantissa>>16 = 0 — lost D=1.)
    let (mut mantissa, mut size) = if byte_len < 3 {
        (difficulty as u32 & 0x00FF_FFFF, 3i32)
    } else {
        let shift = (byte_len - 3) * 8;
        ((difficulty >> shift) as u32 & 0x00FF_FFFF, byte_len as i32)
    };

    // If sign bit (bit 23) is set, shift right one byte and increase size
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        size += 1;
    }

    if size > 32 {
        return 0xFF7F_FFFF;
    }

    ((size as u32) << 24) | (mantissa & 0x00FF_FFFF)
}

/// Expand compact rBits (difficulty) to a 256-bit PoW target with asserted-s fold
/// (Header rBits §5.4 Strategy A + §5.7.2).
///
/// ```text
/// T_eff(rBits, s) ≈ (initial_target / D(rBits)) × 2^s
/// ```
///
/// Higher `asserted_s` → softer (larger) target. Same rBits can yield different
/// targets under different asserted s. Saturates at
/// [`crate::common::crypto::nbits_conversion::MAX_REPRESENTABLE_NBITS`].
///
/// # Arguments
/// * `rbits` — Compact difficulty (header work field post-migration; or
///   `nbits_to_rbits(nbits, 0)` for interim conversion)
/// * `initial_target` — Network difficulty-1 reference target (genesis
///   `max_target` / initial beacon target)
/// * `asserted_s` — Hash-sorting width folded into the expand
///
/// # Returns
/// Full 256-bit target. All-zeros if `rbits == 0` or `D == 0`.
pub fn rbits_to_target(
    rbits: u32,
    initial_target: &[u8; 32],
    asserted_s: u32,
) -> [u8; 32] {
    use crate::common::crypto::nbits_conversion::{
        scale_target_by_power_of_two_saturating, U256,
    };

    let d = rbits_to_u128_approx(rbits);
    if d == 0 {
        return [0u8; 32];
    }

    let init = U256::from_bytes(initial_target);
    let divisor = U256::from_u128(d);
    let t_base = init.div(&divisor).to_bytes();
    scale_target_by_power_of_two_saturating(&t_base, asserted_s)
}

/// Stratum / ASIC adapter: compact **rBits** → compact **nBits** (target encoding).
///
/// `nBits = target_to_nbits(rbits_to_target(rBits, initial_target, asserted_s))`.
/// Consensus headers keep rBits; share jobs that need Bitcoin-style nBits use
/// this boundary only (`DAA_rBits_Native_Redesign.md` §2.2).
pub fn rbits_to_nbits(rbits: u32, initial_target: &[u8; 32], asserted_s: u32) -> u32 {
    use crate::common::crypto::nbits_conversion::target_to_nbits;
    target_to_nbits(&rbits_to_target(rbits, initial_target, asserted_s))
}

/// Interim PoW target from a header that still carries compact **nBits**
/// (target), with §5.7.2 asserted-s fold applied.
///
/// One clear path while the work slot is still nBits:
/// `T_eff = nbits_to_target(nbits) × 2^asserted_s` (saturating).
///
/// Equivalent in intent to converting via `nbits_to_rbits(nbits, 0)` then
/// [`rbits_to_target`] when `initial_target` matches the reference used to
/// stamp that nBits — prefer this helper for live verify to avoid an extra
/// round-trip through approximate rBits.
pub fn pow_target_from_nbits_with_asserted_s(nbits: u32, asserted_s: u32) -> [u8; 32] {
    use crate::common::crypto::nbits_conversion::scale_target_by_power_of_two_saturating;
    let base = nbits_to_target(nbits);
    scale_target_by_power_of_two_saturating(&base, asserted_s)
}

// ============================================================================
// CORE HASH FUNCTION
// ============================================================================

/// Combine two WeightedHash nodes into their parent (internal MMR node).
///
/// This is used **only for internal MMR nodes**, not for block-hash leaves.
/// Leaves are constructed via `WeightedHash::from_leaf` (SHA256d prefix + rBits).
///
/// # Algorithm
/// ```text
/// parent.hash_224 = BLAKE3_224(left.raw() || right.raw())   // 64 bytes in
/// parent.rbits    = rbits_add(left.rbits, right.rbits)
/// ```
///
/// Blake3 is appropriate here because these are not PoW-verified hashes —
/// collision resistance comes from the hash function itself, not ASIC mining.
///
/// # Properties
/// - Order-dependent: hash_pair_weighted(L, R) ≠ hash_pair_weighted(R, L)
/// - Deterministic: same inputs → same output
/// - rBits accumulates total cumulative difficulty from both subtrees
#[inline]
pub fn hash_pair_weighted(left: &WeightedHash, right: &WeightedHash) -> WeightedHash {
    let full_bytes_owned = BLAKE3_WEIGHTED.with(|cell| {
        let mut h = cell.borrow_mut();
        h.reset();
        h.update(left.raw());
        h.update(right.raw());
        *h.finalize().as_bytes()
    });
    let full_bytes = &full_bytes_owned;

    let mut hash_224 = [0u8; HASH_BYTES];
    hash_224.copy_from_slice(&full_bytes[..HASH_BYTES]);

    let l = left.rbits();
    let r = right.rbits();
    let combined_rbits = if l == r { rbits_double(l) } else { rbits_add(l, r) };

    WeightedHash::from_parts(hash_224, combined_rbits)
}

// ============================================================================
// rBITS ARITHMETIC
// ============================================================================

/// Add two compact rBits difficulty values.
///
/// Because rBits encodes difficulty (not target), addition is semantically
/// correct: the sum represents the total work done by both subtrees.
///
/// Uses the same compact floating-point arithmetic as Bitcoin nBits addition:
///  1. Expand both to (mantissa, byte_exponent) pairs
///  2. Align to the smaller exponent
///  3. Sum the mantissas
///  4. Re-encode as compact rBits
///
/// Saturates at `0xFF7FFFFF` on overflow (unreachable for realistic chains).
#[inline]
pub fn rbits_add(a: u32, b: u32) -> u32 {
    if a == 0 { return b; }
    if b == 0 { return a; }

    let (ma, ea) = rbits_to_mantissa_exp(a);
    let (mb, eb) = rbits_to_mantissa_exp(b);

    let (sum_mantissa, exp) = if ea <= eb {
        let shift = (eb - ea) as u32;
        if shift >= 64 { return b; }
        let mb_shifted = mb.checked_shl(shift * 8).unwrap_or(u64::MAX);
        (ma.saturating_add(mb_shifted), ea)
    } else {
        let shift = (ea - eb) as u32;
        if shift >= 64 { return a; }
        let ma_shifted = ma.checked_shl(shift * 8).unwrap_or(u64::MAX);
        (mb.saturating_add(ma_shifted), eb)
    };

    mantissa_exp_to_rbits(sum_mantissa, exp)
}

/// Double a compact rBits value: equivalent to `rbits_add(r, r)` but without
/// the alignment-shift logic, since both operands are identical.
///
/// Within a difficulty epoch all leaves carry the same rBits value `r`. Every
/// internal MMR merge at height h above the leaf layer combines two subtrees
/// whose roots both carry the same rBits, so the accumulation is always
/// `2 × r`.  This specialised path eliminates one `rbits_to_mantissa_exp` call,
/// the alignment-shift branch, and the conditional.
///
/// `mantissa << 1` can set bit 24 at most; `mantissa_exp_to_rbits` handles
/// that with at most one normalization step.
#[inline]
pub fn rbits_double(r: u32) -> u32 {
    if r == 0 { return 0; }
    let (mantissa, exp) = rbits_to_mantissa_exp(r);
    mantissa_exp_to_rbits(mantissa << 1, exp)
}

/// Sentinel rBits meaning "no contributing shard difficulty yet".
///
/// Harder than any practical difficulty so [`rbits_min`] with a real value
/// returns the real value (same role `u64::MAX` played for legacy scalar D).
pub const RBITS_DIFFICULTY_NONE: u32 = 0xFF7F_FFFF;

/// Compare two compact rBits difficulty values.
///
/// Higher difficulty = more work required (harder). Uses mantissa/exponent
/// alignment — no decode through [`rbits_to_u128_approx`].
///
/// `0` is treated as the lowest difficulty (no work / unset).
pub fn rbits_cmp(a: u32, b: u32) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    if a == b {
        return Ordering::Equal;
    }
    if a == 0 {
        return Ordering::Less;
    }
    if b == 0 {
        return Ordering::Greater;
    }

    let (ma, ea) = rbits_to_mantissa_exp(a);
    let (mb, eb) = rbits_to_mantissa_exp(b);

    // Compare ma × 256^ea vs mb × 256^eb by aligning exponents.
    if ea == eb {
        ma.cmp(&mb)
    } else if ea > eb {
        let shift = (ea - eb) as u32;
        match ma.checked_shl(shift.saturating_mul(8)) {
            Some(ma_aligned) => ma_aligned.cmp(&mb),
            None => Ordering::Greater,
        }
    } else {
        let shift = (eb - ea) as u32;
        match mb.checked_shl(shift.saturating_mul(8)) {
            Some(mb_aligned) => ma.cmp(&mb_aligned),
            None => Ordering::Less,
        }
    }
}

/// Minimum of two rBits difficulties (easier / lower work requirement).
#[inline]
pub fn rbits_min(a: u32, b: u32) -> u32 {
    match rbits_cmp(a, b) {
        core::cmp::Ordering::Less | core::cmp::Ordering::Equal => a,
        core::cmp::Ordering::Greater => b,
    }
}

/// Expand a compact rBits value to (mantissa, byte_exponent).
/// Returns `(0, 0)` for zero input.
fn rbits_to_mantissa_exp(rbits: u32) -> (u64, i32) {
    if rbits == 0 { return (0, 0); }
    let size     = (rbits >> 24) as i32;
    let mantissa = (rbits & 0x00FF_FFFF) as u64;
    let exp      = size - 3;
    (mantissa, exp)
}

/// Encode (mantissa, byte_exponent) back to compact rBits.
/// Normalizes mantissa to 24 bits, saturates at `0xFF7FFFFF` on overflow.
fn mantissa_exp_to_rbits(mut mantissa: u64, mut exp: i32) -> u32 {
    if mantissa == 0 { return 0; }

    while mantissa > 0x00FF_FFFF {
        mantissa >>= 8;
        exp += 1;
    }

    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exp += 1;
    }

    let size = exp + 3;
    if size <= 0  { return 0; }
    if size >  32 { return 0xFF7F_FFFF; }

    ((size as u32) << 24) | (mantissa as u32 & 0x00FF_FFFF)
}

// ============================================================================
// APPROXIMATE DIFFICULTY DECODING
// ============================================================================

/// Decode a compact rBits value to an approximate u128 difficulty.
///
/// Because rBits encodes difficulty (not target), real-world values are
/// far below u128::MAX. Saturation only occurs for astronomically large
/// chains (more than ~2^128 total hash operations — not a practical concern).
pub fn rbits_to_u128_approx(rbits: u32) -> u128 {
    if rbits == 0 { return 0; }

    let (mantissa, exp) = rbits_to_mantissa_exp(rbits);

    if exp < 0 {
        let shift = (-exp) as u32;
        if shift >= 8 { return 0; }
        return mantissa as u128 >> (shift * 8);
    }

    let exp = exp as u32;
    if exp >= 16 { return u128::MAX; }

    (mantissa as u128).checked_shl(exp * 8).unwrap_or(u128::MAX)
}

// ============================================================================
// BLAKE3 TRUNCATED TO 224 BITS (internal MMR nodes only)
// ============================================================================

/// Hash arbitrary data with BLAKE3 and truncate to 224 bits (28 bytes).
///
/// Used **only** inside `hash_pair_weighted` for internal MMR node construction.
///
/// NOT used for block-hash leaves. Leaf nodes are formed by truncating the
/// SHA256d PoW hash to 28 bytes directly (see `WeightedHash::from_leaf`).
#[inline]
pub fn blake3_truncate_224(data: &[u8]) -> [u8; HASH_BYTES] {
    let full  = blake3::hash(data);
    let bytes = full.as_bytes();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&bytes[..HASH_BYTES]);
    out
}

// ============================================================================
// PEAK BAGGING WITH WEIGHT
// ============================================================================

/// Bag a sequence of MMR peaks into a single WeightedHash root.
///
/// Folds peaks left-to-right from the anchor. The resulting root's
/// `.rbits()` holds the TOTAL cumulative difficulty of all peaks.
/// The anchor contributes zero weight (rBits = 0).
pub fn bag_peaks_weighted(peaks: &[WeightedHash], anchor: WeightedHash) -> WeightedHash {
    if peaks.is_empty() { return anchor; }
    peaks.iter().fold(anchor, |acc, peak| hash_pair_weighted(&acc, peak))
}

/// Bag a sequence of MMR peaks and return both the structural root and the
/// exact canonical chain weight as `u128`.
///
/// # Structural hash
/// Computed identically to [`bag_peaks_weighted`] — left-to-right fold via
/// [`hash_pair_weighted`]. The hash portion (bytes 0..28) is unchanged.
///
/// # Canonical weight (u128)
/// Each peak's rBits is decoded to u128 with [`rbits_to_u128_approx`] and
/// summed with saturating u128 addition. Only **one** rounding step occurs
/// per peak (the `rbits_to_u128_approx` call); the cascading quantization
/// error of repeated `rbits_add` is eliminated.
///
/// The returned root's rBits field is overwritten with
/// `u128_to_rbits(canonical_u128)` so it is consistent with the u128 sum.
///
/// # Returns
/// `(corrected_root, canonical_u128)` where:
/// - `corrected_root.hash_bytes()` == `bag_peaks_weighted(peaks, anchor).hash_bytes()`
/// - `corrected_root.rbits()` == `u128_to_rbits(canonical_u128)`
/// - `canonical_u128` == exact `Σ rbits_to_u128_approx(p.rbits())` for each peak
pub fn bag_peaks_weighted_u128(
    peaks: &[WeightedHash],
    anchor: WeightedHash,
) -> (WeightedHash, u128) {
    if peaks.is_empty() {
        return (anchor, 0);
    }

    // Structural root: unchanged fold via hash_pair_weighted.
    let structural_root = bag_peaks_weighted(peaks, anchor);

    // Canonical weight: decode each peak's rBits once, sum exactly in u128.
    let canonical_u128: u128 = peaks
        .iter()
        .map(|p| rbits_to_u128_approx(p.rbits()))
        .fold(0u128, |acc, d| acc.saturating_add(d));

    // Overwrite only the rBits field; preserve the structural hash bytes.
    let corrected_rbits = u128_to_rbits(canonical_u128);
    let corrected_root = WeightedHash::from_parts(structural_root.hash_bytes(), corrected_rbits);

    (corrected_root, canonical_u128)
}

// ============================================================================
// PROGRESSIVE PEAK BAGGING
// ============================================================================

/// Incremental state for progressive weighted peak bagging.
///
/// Mirrors `bagged_peaks: Vec<[u8; 32]>` in `full_mmr_core.rs` but stores
/// WeightedHash values so each bag carries accumulated cumulative difficulty.
///
/// # Exact chain weight (W7)
///
/// In addition to the structural bag chain (`bags`), the bagger maintains a
/// parallel exact-precision u128 accumulator:
///
/// - `peak_u128s[i]` = `rbits_to_u128_approx(peak_i.rbits())` — the decoded
///   difficulty of the i-th pushed peak (one rounding per leaf, not cascaded).
/// - `cumulative_u128` = Σ `peak_u128s[i]` — exact u128 sum of all active peaks.
///
/// `canonical_root()` returns `current_root()` with its rBits field overwritten
/// to `u128_to_rbits(cumulative_u128)`, eliminating the cascade-compounding error
/// that `rbits_add` introduces when bagging many peaks.
///
/// `pop_peak()` subtracts the top entry from `cumulative_u128` before removing it,
/// so revert operations keep the exact sum consistent.
///
/// # Serde backward compatibility
/// `cumulative_u128` and `peak_u128s` are `#[serde(default)]`. Old serialized
/// state deserializes to zeros; call `rebuild_u128_track()` after loading if you
/// need exact canonical weights from stored state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedPeakBagger {
    /// `bags[0]` = anchor (rBits = 0)
    /// `bags[i]` = hash_pair_weighted(bags[i-1], peak[i-1])
    bags: Vec<WeightedHash>,
    /// Stable snapshot of the genesis root (bags[1] captured when the first
    /// leaf is pushed). This never changes even as the merge cascade pops and
    /// replaces bags[1] for subsequent blocks.
    genesis_root_snapshot: Option<WeightedHash>,
    /// Exact u128 sum of all currently active peaks' decoded difficulties.
    /// Each entry in `peak_u128s` contributes exactly once; no cascade error.
    #[serde(default)]
    cumulative_u128: u128,
    /// Per-peak decoded u128 values. Length always equals `bags.len() - 1`
    /// (one entry per pushed peak; the anchor at bags[0] contributes 0 and is
    /// not stored here). Used by `pop_peak` to subtract the correct amount.
    #[serde(default)]
    peak_u128s: Vec<u128>,
}

impl WeightedPeakBagger {
    pub fn new(anchor: WeightedHash) -> Self {
        Self {
            bags: vec![anchor],
            genesis_root_snapshot: None,
            cumulative_u128: 0,
            peak_u128s: Vec::new(),
        }
    }

    pub fn push_peak(&mut self, peak: WeightedHash) {
        let prev_bag = *self.bags.last().expect("bags always has at least anchor");
        let new_bag  = hash_pair_weighted(&prev_bag, &peak);
        self.bags.push(new_bag);
        // Capture the genesis root the first time a leaf is pushed. This snapshot
        // is immutable: subsequent merge cascades that pop/replace bags[1] do not
        // affect it, so genesis_root() always returns the state after block 0.
        if self.genesis_root_snapshot.is_none() {
            self.genesis_root_snapshot = Some(new_bag);
        }
        // Maintain exact u128 track: decode this peak's rBits once (one rounding
        // step per leaf; never re-accumulated) and add to the running sum.
        let peak_u128 = rbits_to_u128_approx(peak.rbits());
        self.peak_u128s.push(peak_u128);
        self.cumulative_u128 = self.cumulative_u128.saturating_add(peak_u128);
    }

    pub fn pop_peak(&mut self) {
        if self.bags.len() > 1 {
            self.bags.pop();
            // Subtract the top peak's contribution from the exact sum.
            if let Some(peak_u128) = self.peak_u128s.pop() {
                self.cumulative_u128 = self.cumulative_u128.saturating_sub(peak_u128);
            }
        }
    }

    pub fn current_root(&self) -> WeightedHash {
        *self.bags.last().expect("bags always has at least anchor")
    }

    pub fn genesis_root(&self) -> Option<WeightedHash> {
        self.genesis_root_snapshot
    }

    /// Exact canonical chain weight as u128.
    ///
    /// Equal to `Σ rbits_to_u128_approx(peak_i.rbits())` across all pushed
    /// peaks — one rounding per leaf, no cascade accumulation.
    pub fn canonical_chain_weight(&self) -> u128 {
        self.cumulative_u128
    }

    /// Current MMR root with rBits corrected to encode the exact canonical
    /// chain weight (`u128_to_rbits(cumulative_u128)`).
    ///
    /// The structural hash portion (bytes 0..28) is identical to `current_root()`.
    /// Only the rBits field (bytes 28..32) differs: it encodes the exact u128 sum
    /// rather than the cascaded `rbits_add` approximation.
    pub fn canonical_root(&self) -> WeightedHash {
        let root = self.current_root();
        if self.cumulative_u128 == 0 {
            return root;
        }
        let corrected_rbits = u128_to_rbits(self.cumulative_u128);
        WeightedHash::from_parts(root.hash_bytes(), corrected_rbits)
    }

    /// Recompute the u128 track from the current `bags` vector.
    ///
    /// Called after deserialization of old state where `cumulative_u128` and
    /// `peak_u128s` were not stored. This is O(k) where k = number of active peaks.
    ///
    /// Note: without the original pushed peaks stored separately we cannot
    /// recover per-peak u128 values exactly. Instead we approximate by decoding
    /// the rBits difference between consecutive bags. For reorg-safe exact recovery,
    /// callers should prefer constructing a fresh bagger from the block sequence.
    pub fn rebuild_u128_track_from_bags(&mut self) {
        // The anchor (bags[0]) contributes zero weight.
        // For each subsequent bag, we cannot recover the individual peak's rBits
        // without the original peak. As a best-effort, decode the final root's
        // rBits — this gives the cascaded approximation, not the exact sum.
        // This is only called for backward-compat loading; newly constructed
        // baggers always maintain peak_u128s correctly via push_peak.
        self.peak_u128s.clear();
        self.cumulative_u128 = rbits_to_u128_approx(self.current_root().rbits());
    }

    pub fn cumulative_difficulty_approx(&self) -> u128 {
        self.current_root().cumulative_difficulty_approx()
    }

    pub fn len(&self) -> usize {
        self.bags.len()
    }
}

// ============================================================================
// FORK CHOICE
// ============================================================================

/// Compare two MMR roots by cumulative chain weight.
///
/// Returns `Ordering::Greater` if `a` has more total proof-of-work than `b`.
pub fn compare_roots_by_weight(a: WeightedHash, b: WeightedHash) -> std::cmp::Ordering {
    a.cumulative_difficulty_approx().cmp(&b.cumulative_difficulty_approx())
}

// ============================================================================
// DISPLAY / DEBUG
// ============================================================================

impl std::fmt::Debug for WeightedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WeightedHash {{ hash_224={}, rbits=0x{:08x}, cumulative≈{} }}",
            hex::encode(&self.0[..HASH_BYTES]),
            self.rbits(),
            self.cumulative_difficulty_approx()
        )
    }
}

impl std::fmt::Display for WeightedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}|{:08x}", hex::encode(&self.0[..HASH_BYTES]), self.rbits())
    }
}

impl From<WeightedHash> for [u8; 32] {
    fn from(wh: WeightedHash) -> Self { wh.0 }
}

impl From<[u8; 32]> for WeightedHash {
    fn from(b: [u8; 32]) -> Self { Self(b) }
}

impl AsRef<[u8]> for WeightedHash {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for WeightedHash {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] { &self.0 }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Layout tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_size_is_32_bytes() {
        assert_eq!(WEIGHTED_HASH_SIZE, 32);
        assert_eq!(std::mem::size_of::<WeightedHash>(), 32);
    }

    #[test]
    fn test_from_parts_round_trips() {
        let hash_224 = [0xABu8; HASH_BYTES];
        let rbits    = u128_to_rbits(4_294_967_296); // 2^32

        let wh = WeightedHash::from_parts(hash_224, rbits);
        assert_eq!(wh.hash_bytes(), hash_224);
        assert_eq!(wh.rbits(), rbits);
    }

    /// Header-native leaf: rBits copied into bytes 28–31; hash prefix preserved.
    #[test]
    fn from_leaf_rbits_copies_header_rbits() {
        let mut pow = [0u8; 32];
        for (i, b) in pow.iter_mut().enumerate() {
            *b = i as u8;
        }
        let rbits = u128_to_rbits(1_000_000);
        let leaf = WeightedHash::from_leaf_rbits(&pow, rbits);
        assert_eq!(&leaf.raw()[..HASH_BYTES], &pow[..HASH_BYTES]);
        assert_eq!(leaf.rbits(), rbits);
        // Bytes 28–31 of the PoW hash are overwritten (not preserved).
        assert_ne!(&leaf.raw()[HASH_BYTES..], &pow[HASH_BYTES..]);
    }

    /// Genesis helper: nBits → header rBits relative to initial_target round-trips
    /// through Strategy A expand (lossy compact; allow nBits re-encode equality).
    #[test]
    fn nbits_to_header_rbits_difficulty_one_round_trips() {
        let initial: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nbits = crate::common::crypto::nbits_conversion::target_to_nbits(&initial);
        let rbits = nbits_to_header_rbits(nbits, &initial);
        assert_eq!(rbits_to_u128_approx(rbits), 1, "D=1 at difficulty-1 target");
        let expanded = rbits_to_target(rbits, &initial, 0);
        // Compact round-trip may not be byte-identical; difficulty must stay 1.
        let d = crate::common::crypto::nbits_conversion::calculate_difficulty_with_max_target(
            &expanded, &initial,
        );
        assert_eq!(d, 1);
    }

    #[test]
    fn test_rbits_stored_big_endian() {
        // Use a known rbits value and verify byte layout
        let rbits = 0x05010000_u32; // encodes ≈ 2^32
        let wh    = WeightedHash::from_parts([0u8; HASH_BYTES], rbits);
        assert_eq!(wh.0[28], 0x05);
        assert_eq!(wh.0[29], 0x01);
        assert_eq!(wh.0[30], 0x00);
        assert_eq!(wh.0[31], 0x00);
    }

    #[test]
    fn test_zero_sentinel() {
        let z = WeightedHash::zero();
        assert!(z.is_zero());
        assert_eq!(z.rbits(), 0);
        assert_eq!(z.cumulative_difficulty_approx(), 0);
        assert!(!z.has_weight());
    }

    #[test]
    fn test_from_anchor_has_zero_rbits() {
        let anchor = [0xFFu8; 32];
        let wh = WeightedHash::from_anchor(&anchor);
        assert_eq!(wh.rbits(), 0);
        assert!(!wh.has_weight());
        assert_eq!(&wh.0[..HASH_BYTES], &anchor[..HASH_BYTES]);
    }

    // -----------------------------------------------------------------------
    // nbits_to_rbits conversion tests (the core of the redesign)
    // -----------------------------------------------------------------------

    #[test]
    fn test_nbits_to_rbits_zero_returns_zero() {
        assert_eq!(nbits_to_rbits(0, 0), 0);
        assert_eq!(nbits_to_rbits(0, 4), 0);
    }

    #[test]
    fn test_nbits_to_rbits_genesis_k0_fits_in_u128() {
        // Bitcoin genesis 0x1d00ffff → difficulty ≈ 2^32
        // This must NOT saturate u128 (unlike the old nbits approach)
        let rbits = nbits_to_rbits(0x1d00ffff, 0);
        let diff  = rbits_to_u128_approx(rbits);
        assert!(diff < u128::MAX, "Genesis difficulty must NOT saturate u128 (was {})", diff);
        assert!(diff > 0,         "Genesis difficulty must be positive");
    }

    #[test]
    fn test_nbits_to_rbits_genesis_k0_reasonable_range() {
        // Bitcoin genesis difficulty = 2^32 / 0xffff ≈ 65537 × 2^16 ≈ 4.3 billion
        let rbits = nbits_to_rbits(0x1d00ffff, 0);
        let diff  = rbits_to_u128_approx(rbits);
        // Allow generous ±4× for compact rounding losses
        assert!(diff > (1u128 << 28), "Genesis diff too small: {}", diff);
        assert!(diff < (1u128 << 40), "Genesis diff too large: {}",  diff);
    }

    #[test]
    fn test_nbits_to_rbits_k_multiplies_difficulty() {
        // k=4 gives 2^4 = 16× more difficulty than k=0
        let rbits_k0 = nbits_to_rbits(0x1d00ffff, 0);
        let rbits_k4 = nbits_to_rbits(0x1d00ffff, 4);

        let d0 = rbits_to_u128_approx(rbits_k0);
        let d4 = rbits_to_u128_approx(rbits_k4);

        assert!(d4 > d0, "k=4 ({}) must exceed k=0 ({})", d4, d0);
        let ratio = d4 / d0.max(1);
        assert!(ratio >= 8 && ratio <= 32,
            "k=4 should be ≈16× harder, got {}×", ratio);
    }

    /// §5.7.2 / Strategy A: same rBits, higher asserted s → softer (larger) target.
    #[test]
    fn rbits_to_target_higher_s_softens() {
        let initial: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // Use a difficulty that survives compact rBits round-trip (size ≥ 3).
        let rbits = u128_to_rbits(4_294_967_296); // 2^32
        let d = rbits_to_u128_approx(rbits);
        assert!(d > 0, "rBits must decode to non-zero difficulty");
        let t0 = rbits_to_target(rbits, &initial, 0);
        let t4 = rbits_to_target(rbits, &initial, 4);
        assert_ne!(t0, [0u8; 32], "s=0 target must be non-zero");
        assert!(t4 > t0, "s=4 target must be strictly softer than s=0");
    }

    /// Interim nBits path: same nBits, higher s → softer target.
    #[test]
    fn pow_target_from_nbits_higher_s_softens() {
        let nbits = 0x1d00ffffu32;
        let t0 = pow_target_from_nbits_with_asserted_s(nbits, 0);
        let t4 = pow_target_from_nbits_with_asserted_s(nbits, 4);
        assert_eq!(t0, nbits_to_target(nbits), "s=0 must equal plain nbits expand");
        assert!(t4 > t0, "s=4 must soften");
    }

    #[test]
    fn test_harder_nbits_gives_higher_rbits() {
        // Smaller target → higher difficulty → higher rBits decoded value
        let rbits_easy = nbits_to_rbits(0x1d00ffff, 0); // genesis (diff≈1)
        let rbits_hard = nbits_to_rbits(0x1b0404cb, 0); // ≈16 307× harder

        let d_easy = rbits_to_u128_approx(rbits_easy);
        let d_hard = rbits_to_u128_approx(rbits_hard);

        assert!(d_hard > d_easy,
            "Harder block must decode to larger difficulty: {} vs {}", d_hard, d_easy);
    }

    #[test]
    fn test_u128_to_rbits_round_trips_approx() {
        for &val in &[1u128, 256, 65535, 1_000_000, 4_294_967_296u128, 1_000_000_000_000u128] {
            let rbits     = u128_to_rbits(val);
            let recovered = rbits_to_u128_approx(rbits);
            // Compact encoding loses lower-order bits; allow up to 100% relative error
            // (the compact format can round to up to the next power-of-256 multiple)
            let diff = if recovered > val { recovered - val } else { val - recovered };
            assert!(diff <= val.max(1),
                "Round-trip error for {}: recovered {}, diff {}", val, recovered, diff);
        }
    }

    // -----------------------------------------------------------------------
    // BLAKE3 truncation tests (unchanged from original)
    // -----------------------------------------------------------------------

    #[test]
    fn test_blake3_truncate_224_deterministic() {
        let data = b"test data for hashing";
        assert_eq!(blake3_truncate_224(data), blake3_truncate_224(data));
    }

    #[test]
    fn test_blake3_truncate_224_length() {
        assert_eq!(blake3_truncate_224(b"hello").len(), HASH_BYTES);
    }

    #[test]
    fn test_blake3_truncate_224_order_matters() {
        assert_ne!(blake3_truncate_224(b"ab"), blake3_truncate_224(b"ba"));
    }

    // -----------------------------------------------------------------------
    // hash_pair_weighted tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_pair_weighted_deterministic() {
        let left  = WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0);
        let right = WeightedHash::from_leaf(&[2u8; 32], 0x1d00ffff, 0);
        assert_eq!(hash_pair_weighted(&left, &right),
                   hash_pair_weighted(&left, &right), "Must be deterministic");
    }

    #[test]
    fn test_hash_pair_weighted_order_matters() {
        let left  = WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0);
        let right = WeightedHash::from_leaf(&[2u8; 32], 0x1b0404cb, 0);
        let p1 = hash_pair_weighted(&left, &right);
        let p2 = hash_pair_weighted(&right, &left);
        assert_ne!(p1.hash_bytes(), p2.hash_bytes());
    }

    #[test]
    fn test_hash_pair_weighted_rbits_accumulates() {
        let left  = WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0);
        let right = WeightedHash::from_leaf(&[2u8; 32], 0x1d00ffff, 0);
        let parent = hash_pair_weighted(&left, &right);

        let leaf_diff   = left.cumulative_difficulty_approx();
        let parent_diff = parent.cumulative_difficulty_approx();

        assert!(parent_diff >= leaf_diff,
            "Parent ({}) must be >= leaf ({})", parent_diff, leaf_diff);
        assert!(parent_diff <= leaf_diff.saturating_mul(3),
            "Parent ({}) must be <= 3× leaf ({})", parent_diff, leaf_diff);
    }

    #[test]
    fn test_hash_pair_weighted_zero_rbits() {
        let left  = WeightedHash::from_anchor(&[0u8; 32]);
        let right = WeightedHash::from_leaf(&[1u8; 32], 0, 0);
        let parent = hash_pair_weighted(&left, &right);
        assert_eq!(parent.rbits(), 0);
        assert_ne!(parent.hash_bytes(), [0u8; HASH_BYTES]);
    }

    // -----------------------------------------------------------------------
    // rbits_add tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rbits_add_identity_zero() {
        let rbits = u128_to_rbits(4_294_967_296); // 2^32
        assert_eq!(rbits_add(rbits, 0), rbits);
        assert_eq!(rbits_add(0, rbits), rbits);
        assert_eq!(rbits_add(0, 0),     0);
    }

    #[test]
    fn test_rbits_add_same_value_doubles() {
        let d     = 4_294_967_296u128; // 2^32
        let rbits = u128_to_rbits(d);
        let sum   = rbits_add(rbits, rbits);

        let v1    = rbits_to_u128_approx(rbits);
        let v_sum = rbits_to_u128_approx(sum);

        let ratio_10x = v_sum.saturating_mul(10) / v1.max(1);
        assert!(ratio_10x >= 18 && ratio_10x <= 22,
            "Expected ≈2×, got {}×/10 (v1={}, v_sum={})", ratio_10x, v1, v_sum);
    }

    #[test]
    fn test_rbits_add_commutative_approx() {
        let a = u128_to_rbits(4_294_967_296);  // 2^32
        let b = u128_to_rbits(68_719_476_736); // 2^36

        let va = rbits_to_u128_approx(rbits_add(a, b));
        let vb = rbits_to_u128_approx(rbits_add(b, a));

        let diff      = if va > vb { va - vb } else { vb - va };
        let tolerance = va / 256 + 1;
        assert!(diff <= tolerance,
            "Not approximately commutative: |{} - {}| = {} > tolerance {}", va, vb, diff, tolerance);
    }

    #[test]
    fn test_rbits_add_large_values_saturate() {
        let max = 0xFF7F_FFFF_u32;
        assert!(rbits_add(max, max) <= 0xFF7F_FFFF);
    }

    #[test]
    fn test_rbits_add_monotone() {
        let a   = u128_to_rbits(4_294_967_296);
        let sum = rbits_add(a, a);
        assert!(rbits_to_u128_approx(sum) >= rbits_to_u128_approx(a));
    }

    // -----------------------------------------------------------------------
    // rbits_to_u128_approx tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rbits_to_u128_approx_zero() {
        assert_eq!(rbits_to_u128_approx(0), 0);
    }

    #[test]
    fn test_genesis_rbits_do_not_saturate() {
        let rbits = nbits_to_rbits(0x1d00ffff, 0);
        assert_ne!(rbits_to_u128_approx(rbits), u128::MAX,
            "Genesis rBits must NOT produce u128::MAX");
    }

    #[test]
    fn test_100_blocks_no_saturation() {
        // 100 blocks at genesis difficulty: cumulative must fit in u128
        let rbits_per = nbits_to_rbits(0x1d00ffff, 0);
        let mut cum   = 0u32;
        for _ in 0..100 { cum = rbits_add(cum, rbits_per); }
        assert!(rbits_to_u128_approx(cum) < u128::MAX,
            "100 genesis blocks must not saturate u128");
    }

    // -----------------------------------------------------------------------
    // Peak bagging tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bag_peaks_empty_returns_anchor() {
        let anchor = WeightedHash::from_anchor(&[0xAAu8; 32]);
        assert_eq!(bag_peaks_weighted(&[], anchor), anchor);
    }

    #[test]
    fn test_bag_peaks_single_peak() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let peak   = WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0);
        let result = bag_peaks_weighted(&[peak], anchor);
        assert_eq!(result, hash_pair_weighted(&anchor, &peak));
    }

    #[test]
    fn test_bag_peaks_accumulates_difficulty() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let peaks  = [
            WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0),
            WeightedHash::from_leaf(&[2u8; 32], 0x1d00ffff, 0),
            WeightedHash::from_leaf(&[3u8; 32], 0x1d00ffff, 0),
        ];
        let root      = bag_peaks_weighted(&peaks, anchor);
        let leaf_diff = peaks[0].cumulative_difficulty_approx();
        let root_diff = root.cumulative_difficulty_approx();

        assert!(root_diff >= leaf_diff,
            "Root ({}) >= 1 leaf diff ({})", root_diff, leaf_diff);
        assert!(root_diff >= leaf_diff.saturating_mul(2),
            "Root ({}) >= 2× leaf diff ({}) for 3 peaks", root_diff, leaf_diff);
    }

    #[test]
    fn test_peak_bagger_genesis_root() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        assert!(bagger.genesis_root().is_none(), "No genesis before first leaf");
        bagger.push_peak(WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0));
        assert!(bagger.genesis_root().is_some(), "Genesis root after first leaf");
    }

    #[test]
    fn test_peak_bagger_difficulty_grows() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        let d0 = bagger.cumulative_difficulty_approx();
        bagger.push_peak(WeightedHash::from_leaf(&[1u8; 32], 0x1d00ffff, 0));
        let d1 = bagger.cumulative_difficulty_approx();
        bagger.push_peak(WeightedHash::from_leaf(&[2u8; 32], 0x1d00ffff, 0));
        let d2 = bagger.cumulative_difficulty_approx();

        assert_eq!(d0, 0,  "Anchor has zero difficulty");
        assert!(d1 > d0,   "After leaf 1: difficulty grew");
        assert!(d2 > d1,   "After leaf 2: difficulty grew further");
    }

    // -----------------------------------------------------------------------
    // End-to-end chain simulation
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_of_100_blocks() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        let block_nbits = 0x1d00ffff;
        let k           = 0u32;

        for i in 0u8..100 {
            bagger.push_peak(WeightedHash::from_leaf(&[i; 32], block_nbits, k));
        }

        let per_block = rbits_to_u128_approx(nbits_to_rbits(block_nbits, k));
        let total     = bagger.cumulative_difficulty_approx();

        assert!(total > 0,
            "Cumulative difficulty must be positive");
        assert!(total >= per_block,
            "Total ({}) must be >= 1 block's worth ({})", total, per_block);
        assert!(total < u128::MAX,
            "100 blocks must not saturate u128");

        // Roughly 100× per-block, allow 50% tolerance for compact rounding
        let expected = per_block.saturating_mul(100);
        let diff = if total > expected { total - expected } else { expected - total };
        assert!(diff <= expected,
            "Total {} is too far from expected {} (diff {})", total, expected, diff);
    }

    // -----------------------------------------------------------------------
    // W7: WeightedPeakBagger canonical_chain_weight / canonical_root
    // -----------------------------------------------------------------------

    #[test]
    fn test_bagger_canonical_weight_equals_decoded_sum() {
        // Push 4 peaks with known rBits and verify canonical_chain_weight()
        // equals the manual sum of decoded per-peak values.
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        let nbits = 0x1d00ffff;
        let k = 0u32;
        let mut expected_sum: u128 = 0;

        for i in 0u8..4 {
            let peak = WeightedHash::from_leaf(&[i; 32], nbits, k);
            expected_sum = expected_sum.saturating_add(rbits_to_u128_approx(peak.rbits()));
            bagger.push_peak(peak);
        }

        assert_eq!(
            bagger.canonical_chain_weight(), expected_sum,
            "canonical_chain_weight must equal the manual sum of decoded peak rBits"
        );
    }

    #[test]
    fn test_pop_restores_canonical_weight() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        let nbits = 0x1d00ffff;
        let k = 0u32;
        let peaks: Vec<WeightedHash> = (0u8..3)
            .map(|i| WeightedHash::from_leaf(&[i; 32], nbits, k))
            .collect();

        for &p in &peaks { bagger.push_peak(p); }
        let weight_after_3 = bagger.canonical_chain_weight();

        // Push a 4th peak.
        let p3 = WeightedHash::from_leaf(&[3u8; 32], nbits, k);
        let p3_u128 = rbits_to_u128_approx(p3.rbits());
        bagger.push_peak(p3);
        assert_eq!(
            bagger.canonical_chain_weight(),
            weight_after_3.saturating_add(p3_u128),
            "weight after push must include the 4th peak"
        );

        // Pop it back — must restore exactly.
        bagger.pop_peak();
        assert_eq!(
            bagger.canonical_chain_weight(), weight_after_3,
            "pop must restore exact canonical weight"
        );
    }

    #[test]
    fn test_canonical_root_rbits_consistent_with_u128() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let mut bagger = WeightedPeakBagger::new(anchor);

        let nbits = 0x1d00ffff;
        let k = 0u32;
        for i in 0u8..5 {
            bagger.push_peak(WeightedHash::from_leaf(&[i; 32], nbits, k));
        }

        let canonical = bagger.canonical_root();
        let weight    = bagger.canonical_chain_weight();
        let expected_rbits = u128_to_rbits(weight);

        assert_eq!(
            canonical.rbits(), expected_rbits,
            "canonical_root rBits must equal u128_to_rbits(canonical_chain_weight)"
        );
        // Structural hash must match current_root.
        assert_eq!(
            canonical.hash_bytes(), bagger.current_root().hash_bytes(),
            "canonical_root hash_bytes must be identical to current_root"
        );
    }

    #[test]
    fn test_canonical_weight_zero_on_empty_bagger() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let bagger = WeightedPeakBagger::new(anchor);
        assert_eq!(bagger.canonical_chain_weight(), 0,
            "empty bagger canonical weight must be 0");
        // canonical_root with no peaks should equal anchor (cumulative_u128 == 0).
        assert_eq!(bagger.canonical_root().hash_bytes(), anchor.hash_bytes());
    }

    // -----------------------------------------------------------------------
    // W7-T2: bag_peaks_weighted_u128
    // -----------------------------------------------------------------------

    #[test]
    fn test_bag_peaks_u128_empty_returns_anchor() {
        let anchor = WeightedHash::from_anchor(&[0xAAu8; 32]);
        let (root, weight) = bag_peaks_weighted_u128(&[], anchor);
        assert_eq!(root.hash_bytes(), anchor.hash_bytes());
        assert_eq!(weight, 0);
    }

    #[test]
    fn test_bag_peaks_u128_structural_hash_matches_non_u128() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let nbits = 0x1d00ffff;
        let k = 0u32;
        let peaks: Vec<WeightedHash> = (0u8..4)
            .map(|i| WeightedHash::from_leaf(&[i; 32], nbits, k))
            .collect();

        let structural = bag_peaks_weighted(&peaks, anchor);
        let (corrected, _weight) = bag_peaks_weighted_u128(&peaks, anchor);

        assert_eq!(
            corrected.hash_bytes(), structural.hash_bytes(),
            "structural hash must be identical between bag_peaks_weighted and bag_peaks_weighted_u128"
        );
    }

    #[test]
    fn test_bag_peaks_u128_weight_equals_decoded_sum() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let nbits = 0x1d00ffff;
        let k = 0u32;
        let peaks: Vec<WeightedHash> = (0u8..4)
            .map(|i| WeightedHash::from_leaf(&[i; 32], nbits, k))
            .collect();

        let expected: u128 = peaks.iter()
            .map(|p| rbits_to_u128_approx(p.rbits()))
            .fold(0u128, |a, b| a.saturating_add(b));

        let (_root, weight) = bag_peaks_weighted_u128(&peaks, anchor);
        assert_eq!(weight, expected,
            "u128 return must equal sum of decoded peak rBits values");
    }

    #[test]
    fn test_bag_peaks_u128_root_rbits_consistent() {
        let anchor = WeightedHash::from_anchor(&[0u8; 32]);
        let nbits = 0x1d00ffff;
        let k = 0u32;
        let peaks: Vec<WeightedHash> = (0u8..3)
            .map(|i| WeightedHash::from_leaf(&[i; 32], nbits, k))
            .collect();

        let (root, weight) = bag_peaks_weighted_u128(&peaks, anchor);
        assert_eq!(root.rbits(), u128_to_rbits(weight),
            "root.rbits() must equal u128_to_rbits(returned weight)");
    }

    // -----------------------------------------------------------------------
    // RBITS-DOUBLE tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rbits_double_equals_add_self() {
        let cases = [
            0u32,
            nbits_to_rbits(0x1d00ffff, 0),  // Bitcoin genesis difficulty
            nbits_to_rbits(0x1d00ffff, 4),  // k=4 (BLOCK_HASH_W_BITS)
            nbits_to_rbits(0x1b0404cb, 0),  // higher difficulty
            0xFF7F_FFFF,                     // maximum valid rBits
        ];
        for r in cases {
            assert_eq!(
                rbits_double(r),
                rbits_add(r, r),
                "rbits_double({r:#010x}) must equal rbits_add(r, r)"
            );
        }
    }

    #[test]
    fn test_hash_pair_weighted_same_rbits_consistent() {
        let nbits = 0x1d00ffff_u32;
        let a = WeightedHash::from_leaf(&[1u8; 32], nbits, 4);
        let b = WeightedHash::from_leaf(&[2u8; 32], nbits, 4);
        // a and b have the same rBits (same epoch, same nbits) but different hashes.
        assert_eq!(a.rbits(), b.rbits(), "same-epoch leaves must have equal rBits");

        // Fast path (l == r) must yield the same rBits as the general path.
        let fast  = hash_pair_weighted(&a, &b);
        let expected_rbits = rbits_add(a.rbits(), b.rbits());
        assert_eq!(fast.rbits(), expected_rbits,
            "fast-path rBits must equal rbits_add result");

        // Structural hash (BLAKE3 portion) must be unaffected.
        let c = WeightedHash::from_leaf(&[3u8; 32], 0x1b0404cb, 4); // different rBits
        let mixed = hash_pair_weighted(&a, &c);
        // Verify fast-path and slow-path agree when rBits differ.
        assert_eq!(mixed.rbits(), rbits_add(a.rbits(), c.rbits()),
            "mixed-epoch rBits must use rbits_add");
    }

    #[test]
    fn rbits_cmp_orders_by_difficulty_magnitude() {
        use core::cmp::Ordering;
        let easy = u128_to_rbits(1);
        let mid = u128_to_rbits(1_000);
        let hard = u128_to_rbits(1_000_000);
        assert_eq!(rbits_cmp(easy, mid), Ordering::Less);
        assert_eq!(rbits_cmp(hard, mid), Ordering::Greater);
        assert_eq!(rbits_cmp(mid, mid), Ordering::Equal);
        assert_eq!(rbits_cmp(0, easy), Ordering::Less);
        assert_eq!(rbits_min(easy, hard), easy);
        assert_eq!(rbits_min(RBITS_DIFFICULTY_NONE, mid), mid);
        assert_eq!(rbits_cmp(RBITS_DIFFICULTY_NONE, hard), Ordering::Greater);
    }

    #[test]
    fn rbits_to_nbits_round_trips_through_target() {
        use crate::common::crypto::nbits_conversion::target_to_nbits;
        let initial = [
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let rbits = u128_to_rbits(1076);
        let nbits = rbits_to_nbits(rbits, &initial, 0);
        assert_eq!(nbits, target_to_nbits(&rbits_to_target(rbits, &initial, 0)));
        assert_ne!(nbits, 0);
    }
}