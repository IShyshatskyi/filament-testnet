// filament-types/src/relay_hash.rs — F2F relay message dedup id.

/// `BLAKE3(payload)[0..8]`.
pub fn relay_id(payload: &[u8]) -> [u8; 8] {
    let hash = blake3::hash(payload);
    hash.as_bytes()[0..8].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_input_sensitive() {
        assert_eq!(relay_id(b"a"), relay_id(b"a"));
        assert_ne!(relay_id(b"a"), relay_id(b"b"));
    }
}
