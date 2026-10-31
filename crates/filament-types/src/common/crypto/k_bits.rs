/// KBits — compact encoding for the k-coefficient (protocol parameter #2).
///
/// # Format
///
/// ```text
/// kBits = (size_byte << 24) | mantissa_24bit
/// ```
///
/// - `size_byte`    — number of significant bytes in `k_encoded`  (1–16)
/// - `mantissa_24bit` — top 3 significant bytes of `k_encoded`
///
/// Identical in shape to Bitcoin's `nBits` / `target_to_nbits`, but implemented
/// independently to avoid nBits' sign-bit avoidance rule (which is irrelevant for
/// k_encoded, a strictly positive integer).
///
/// # k_encoded
///
/// `k_encoded = round(k × 2^48)` in fixed-point. Mainnet genesis uses k = 1.0
/// (`ONE_KBITS`, `k_encoded = 2^48`). Testnets may start above one (e.g. k = 2^16
/// → `k_encoded = 2^64`) so CPU-mined shard blocks can fund realistic TX-12 fees;
/// k still never *rises* above the network's `k_initial_kbits`.
///
/// - k = 1.0     → `k_encoded = 2^48`,  kBits = `0x07010000`
/// - k = 0.5     → `k_encoded = 2^47`,  kBits = `0x06800000`
/// - k = 2^{-48} → `k_encoded = 1`,     kBits = `0x01010000` (structural floor)
/// - k = 2^16    → `k_encoded = 2^64`,  kBits = `0x09010000` (testnet-stress)
///
/// # Precision
///
/// 24-bit mantissa ≈ 7 significant decimal digits — far more than the 0.1%
/// step resolution required by the voting mechanism (§3.3 of design doc).

/// Maximum size byte accepted by [`decode_kbits_u128`] (u128 significant bytes).
pub const MAX_KBITS_SIZE: u32 = 16;

/// Encode `k_encoded` into KBits compact format (u128 path).
///
/// Returns `0` for `k_encoded == 0` or values that need more than
/// [`MAX_KBITS_SIZE`] significant bytes.
pub fn encode_kbits_u128(k_encoded: u128) -> u32 {
    if k_encoded == 0 {
        return 0;
    }
    let bits = 128 - k_encoded.leading_zeros(); // significant bit count (≥1)
    let size = (bits + 7) / 8; // significant byte count
    if size == 0 || size > MAX_KBITS_SIZE {
        return 0;
    }
    let mantissa: u32 = if size >= 3 {
        let shift = (size - 3) * 8;
        ((k_encoded >> shift) as u32) & 0x00FF_FFFF
    } else {
        let shift = (3 - size) * 8;
        ((k_encoded << shift) as u32) & 0x00FF_FFFF
    };
    (size << 24) | mantissa
}

/// Decode KBits to `k_encoded` as `u128`.
///
/// Returns `0` for invalid inputs (zero, size 0, or size > [`MAX_KBITS_SIZE`]).
pub fn decode_kbits_u128(kbits: u32) -> u128 {
    if kbits == 0 {
        return 0;
    }
    let size = kbits >> 24;
    let mantissa = (kbits & 0x00FF_FFFF) as u128;
    if size == 0 || size > MAX_KBITS_SIZE {
        return 0;
    }
    if size >= 3 {
        mantissa << ((size - 3) * 8)
    } else {
        mantissa >> ((3 - size) * 8)
    }
}

/// Encode `k_encoded` (integer fitting in `u64`) into KBits compact format.
///
/// Returns `0` for `k_encoded == 0`.
pub fn encode_kbits(k_encoded: u64) -> u32 {
    encode_kbits_u128(k_encoded as u128)
}

/// Decode KBits compact format to `k_encoded` as `u64`.
///
/// Returns `0` for invalid inputs, or when the decoded value does not fit in
/// `u64` (use [`decode_kbits_u128`] for k ≥ 2^16 × one).
pub fn decode_kbits(kbits: u32) -> u64 {
    let v = decode_kbits_u128(kbits);
    if v > u64::MAX as u128 {
        return 0;
    }
    v as u64
}

/// Convert KBits to a floating-point k relative to one (`k_encoded / 2^48`).
///
/// Convenience for logging and configuration validation only.
/// All consensus arithmetic (rewards, adjustment) must use [`decode_kbits_u128`]
/// and operate in integer arithmetic.
///
/// Returns `0.0` for invalid inputs. Values above one are representable.
pub fn kbits_to_float(kbits: u32) -> f64 {
    let k_encoded = decode_kbits_u128(kbits);
    if k_encoded == 0 {
        return 0.0;
    }
    k_encoded as f64 / (1u128 << 48) as f64
}

/// Convert a floating-point k to KBits (lossy — 24-bit mantissa precision).
///
/// `k` must be in `(0.0, 2^16]` (covers mainnet one and testnet-stress ×2^16).
/// Returns `0` for out-of-range inputs.
pub fn float_to_kbits(k: f64) -> u32 {
    if k <= 0.0 || k > 65536.0 || k.is_nan() {
        return 0;
    }
    let k_encoded = (k * (1u128 << 48) as f64).round() as u128;
    let max = 1u128 << 64; // k = 2^16
    encode_kbits_u128(k_encoded.max(1).min(max))
}

/// KBits for `k = 2^exp` (relative to the fixed-point one at `2^48`).
///
/// `kbits_times_one_shl(0) == ONE_KBITS`. `kbits_times_one_shl(16)` is the
/// testnet-stress genesis initial k.
pub fn kbits_times_one_shl(exp: u32) -> u32 {
    encode_kbits_u128(1u128 << (48 + exp))
}

/// KBits encoding of k = 1.0 ("one") — mainnet genesis default.
///
/// `k_encoded = 2^48`. Networks may choose a higher `k_initial_kbits`; this
/// constant remains the unit scale for the reward formula's `2^48` denominator.
pub const ONE_KBITS: u32 = 0x0701_0000;

/// KBits encoding of k = 2^16 (testnet-stress genesis initial).
///
/// `k_encoded = 2^64`. Sized so a near-floor shard block (~1 atom at k=1) pays
/// ~2^16 atoms — enough for several TX-12 fees at 16 atoms per 4 bytes.
pub const K_TIMES_2_POW_16_KBITS: u32 = 0x0901_0000;

/// KBits encoding of the structural floor — the smallest representable k.
///
/// `k_encoded = 1` (k = 2^{-48}, one atomic unit of the k scale).
/// This is NOT an economic floor; see K_VOTING_DESIGN_v4.md §0.2.
pub const MIN_KBITS: u32 = 0x0101_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_one() {
        let k_enc = 1u128 << 48;
        let kbits = encode_kbits_u128(k_enc);
        assert_eq!(kbits, ONE_KBITS, "one should encode to 0x07010000");
        assert_eq!(decode_kbits_u128(kbits), k_enc);
        assert_eq!(decode_kbits(kbits), k_enc as u64);
    }

    #[test]
    fn encode_decode_half() {
        let k_enc = 1u64 << 47;
        let kbits = encode_kbits(k_enc);
        assert_eq!(decode_kbits(kbits), k_enc);
        let k_float = kbits_to_float(kbits);
        assert!((k_float - 0.5).abs() < 1e-6);
    }

    #[test]
    fn encode_decode_small() {
        let k_enc: u64 = 1;
        let kbits = encode_kbits(k_enc);
        assert_eq!(kbits, MIN_KBITS, "k_encoded=1 should encode to MIN_KBITS");
        assert_eq!(decode_kbits(kbits), k_enc);
    }

    #[test]
    fn encode_decode_times_2_pow_16() {
        let k_enc = 1u128 << 64;
        let kbits = encode_kbits_u128(k_enc);
        assert_eq!(kbits, K_TIMES_2_POW_16_KBITS);
        assert_eq!(kbits, kbits_times_one_shl(16));
        assert_eq!(decode_kbits_u128(kbits), k_enc);
        // Does not fit in u64 — decode_kbits must return 0, not truncate.
        assert_eq!(decode_kbits(kbits), 0);
        assert!((kbits_to_float(kbits) - 65536.0).abs() < 1e-6);
    }

    #[test]
    fn float_roundtrip() {
        let kbits = float_to_kbits(0.5);
        let k_back = kbits_to_float(kbits);
        assert!((k_back - 0.5).abs() < 1e-6, "float roundtrip within 1 LSB");
    }

    #[test]
    fn float_allows_above_one() {
        let kbits = float_to_kbits(256.0);
        assert_ne!(kbits, 0);
        assert!((kbits_to_float(kbits) - 256.0).abs() / 256.0 < 1e-6);
    }

    #[test]
    fn float_clamp_too_large() {
        assert_eq!(float_to_kbits(65536.1), 0);
    }

    #[test]
    fn float_clamp_zero() {
        assert_eq!(float_to_kbits(0.0), 0);
    }

    #[test]
    fn float_clamp_negative() {
        assert_eq!(float_to_kbits(-0.5), 0);
    }

    #[test]
    fn float_at_one() {
        let kbits = float_to_kbits(1.0);
        assert_eq!(kbits, ONE_KBITS);
        assert!((kbits_to_float(kbits) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn precision_at_step_up() {
        let k = 0.97_f64 * 1.001_f64;
        let kbits = float_to_kbits(k);
        let k_back = kbits_to_float(kbits);
        assert!((k_back - k).abs() / k < 1e-6, "relative error < 1 ppm after roundtrip");
    }

    #[test]
    fn encode_decode_tenth() {
        let k_enc = (0.1_f64 * (1u64 << 48) as f64).round() as u64;
        let kbits = encode_kbits(k_enc);
        assert_eq!(kbits, 0x0619_9999, "k=0.1 should encode to 0x06199999 (design doc table)");
        let decoded = decode_kbits(kbits);
        let diff = if decoded > k_enc { decoded - k_enc } else { k_enc - decoded };
        assert!(diff < (1u64 << 32), "decode precision within 4-byte mantissa error");
    }

    #[test]
    fn zero_input() {
        assert_eq!(encode_kbits(0), 0);
        assert_eq!(decode_kbits(0), 0);
        assert_eq!(kbits_to_float(0), 0.0);
    }

    #[test]
    fn size_byte_correct() {
        let kbits = encode_kbits(256);
        assert_eq!(kbits >> 24, 2);
        assert_eq!(decode_kbits(kbits), 256);
    }

    #[test]
    fn invalid_size_17_returns_zero() {
        let bad_kbits: u32 = (17 << 24) | 0x010000;
        assert_eq!(decode_kbits_u128(bad_kbits), 0);
    }

    #[test]
    fn size_9_accepted_for_2_pow_64() {
        assert_eq!(K_TIMES_2_POW_16_KBITS >> 24, 9);
        assert_eq!(decode_kbits_u128(K_TIMES_2_POW_16_KBITS), 1u128 << 64);
    }
}
