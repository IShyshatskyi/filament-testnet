//! Proof-of-work target arithmetic (clean-room port; checked against the node by the shared vectors).
//!
//! The target for a compact difficulty (rBits) is `initial_target / D`, shifted left by the number
//! of folded sorting bits `s`, and never above the easiest representable target. A hash meets it
//! when, read as a big-endian 256-bit number, it is strictly smaller.

use crate::weighted_hash::rbits_to_u128_approx;

/// The easiest representable target (compact `0x207fffff`): `0x7fffff` in the top three bytes.
const CEILING: [u8; 32] = {
    let mut c = [0u8; 32];
    c[0] = 0x7f;
    c[1] = 0xff;
    c[2] = 0xff;
    c
};

/// `value / divisor` for a big-endian 256-bit value, bit-by-bit long division.
fn div_u128(value: &[u8; 32], divisor: u128) -> [u8; 32] {
    let mut quotient = [0u8; 32];
    let mut rem: u128 = 0;
    for bit in 0..256usize {
        let byte = bit / 8;
        let b = (value[byte] >> (7 - bit % 8)) & 1;
        // rem = rem * 2 + b; track the carry out of 128 bits.
        let carry = rem >> 127;
        rem = (rem << 1) | b as u128;
        if carry == 1 || rem >= divisor {
            rem = rem.wrapping_sub(divisor);
            quotient[byte] |= 1 << (7 - bit % 8);
        }
    }
    quotient
}

fn leading_zero_bits(v: &[u8; 32]) -> u32 {
    let mut n = 0;
    for &b in v {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

fn shift_left(v: &[u8; 32], bits: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let byte_shift = (bits / 8) as usize;
    let bit_shift = bits % 8;
    for i in 0..32 {
        let src = i + byte_shift;
        if src >= 32 {
            break;
        }
        let mut x = (v[src] as u16) << bit_shift;
        if bit_shift > 0 && src + 1 < 32 {
            x |= (v[src + 1] as u16) >> (8 - bit_shift);
        }
        out[i] = x as u8;
    }
    out
}

/// Target for header difficulty `rbits` with `asserted_s` folded sorting bits. All zeros when the
/// difficulty decodes to zero.
pub fn rbits_to_target(rbits: u32, initial_target: &[u8; 32], asserted_s: u32) -> [u8; 32] {
    let d = rbits_to_u128_approx(rbits);
    if d == 0 {
        return [0u8; 32];
    }
    let base = div_u128(initial_target, d);
    if asserted_s == 0 {
        return base;
    }
    if leading_zero_bits(&base) < asserted_s {
        return CEILING;
    }
    let scaled = shift_left(&base, asserted_s);
    if scaled > CEILING {
        return CEILING;
    }
    scaled
}

/// `hash < target`, both read as big-endian numbers (equal is not enough).
pub fn hash_meets_target(hash: &[u8], target: &[u8]) -> bool {
    for i in 0..hash.len().min(target.len()) {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    false
}
