// filament-types/src/hash.rs — plain (non-weighted) BLAKE3 hashing.

use std::cell::RefCell;

thread_local! {
    static BLAKE3_PAIR: RefCell<blake3::Hasher> = RefCell::new(blake3::Hasher::new());
}

/// BLAKE3(left || right) — used for structural (non-weight-carrying) hash
/// pairing, e.g. transaction Merkle trees.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    BLAKE3_PAIR.with(|cell| {
        let mut h = cell.borrow_mut();
        h.reset();
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_pair_is_deterministic_and_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(hash_pair(&a, &b), hash_pair(&a, &b));
        assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
    }
}
