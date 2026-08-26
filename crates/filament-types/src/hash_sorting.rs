// filament-types/src/hash_sorting.rs — shard routing from a PoW hash.
//
// RULE: hash mod 2^k == (shard_id + 1); hash mod 2^k == 0 is reserved (no
// shard). Bits are read from the *trailing* bytes of the hash (never the
// leading byte, which PoW drives toward zero).

pub fn extract_sorting_bits(hash_bytes: &[u8], k: u32) -> u32 {
    if hash_bytes.len() < 32 || k == 0 || k >= 32 {
        return 0;
    }
    let mut result = 0u32;
    let bytes_needed = ((k + 7) / 8) as usize;
    let len = hash_bytes.len();
    for i in 0..bytes_needed.min(len) {
        result |= (hash_bytes[len - 1 - i] as u32) << (i * 8);
    }
    let mask = (1u32 << k) - 1;
    result & mask
}

pub fn find_eligible_shard(hash_bytes: &[u8], k: u32) -> Option<u32> {
    let sorting_bits = extract_sorting_bits(hash_bytes, k);
    if sorting_bits == 0 {
        return None;
    }
    Some(sorting_bits - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sorting_bits_is_reserved() {
        let hash = [0u8; 32];
        assert_eq!(find_eligible_shard(&hash, 4), None);
    }

    #[test]
    fn nonzero_trailing_bits_give_shard_minus_one() {
        let mut hash = [0u8; 32];
        hash[31] = 0b0000_0101; // low 4 bits = 5
        assert_eq!(find_eligible_shard(&hash, 4), Some(4));
    }
}
