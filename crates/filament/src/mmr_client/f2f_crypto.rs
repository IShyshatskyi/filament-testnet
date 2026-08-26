// src/mmr_client/f2f_crypto.rs
//
// F2F-3: Filament-to-Filament message encryption.
//
// Scheme: ephemeral secp256k1 ECDH → BLAKE3 KDF → ChaCha20-Poly1305 AEAD.
//
// Wire format for an encrypted blob:
//   ephemeral_pubkey(33 bytes, compressed) ||
//   nonce(12 bytes)                        ||
//   ciphertext(variable)                   ||
//   poly1305 tag(16 bytes)
//
// The AEAD additional data is the empty byte string (the recipient's address
// is already encoded in the outer relay header, not repeated here).
//
// Key derivation:
//   shared_pt  = ECDH(ephemeral_seckey, recipient_pubkey)   // secp256k1 point
//   key_bytes  = BLAKE3::derive_key("filament f2f v1 aead", &shared_pt.secret_bytes())
//   nonce      = random 12 bytes
//   ciphertext = ChaCha20Poly1305(key_bytes, nonce).encrypt(plaintext)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
    Nonce,
};
use rand::RngExt as _;
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
// secp256k1 0.29 re-exports rand 0.8 internally; use its OsRng to avoid
// the rand_core version mismatch with the workspace rand 0.10.
use secp256k1::rand::rngs::OsRng as SecpOsRng;

const KDF_CONTEXT: &str = "filament f2f v1 aead";
const EPHEM_PK_LEN: usize = 33;
const NONCE_LEN: usize    = 12;
const TAG_LEN: usize      = 16;
const OVERHEAD: usize     = EPHEM_PK_LEN + NONCE_LEN + TAG_LEN;

/// Errors that can occur during F2F encryption/decryption.
#[derive(Debug, PartialEq, Eq)]
pub enum F2fCryptoError {
    /// Ciphertext shorter than the fixed overhead (truncated or corrupt).
    Truncated,
    /// The ephemeral public-key bytes in the blob are not a valid secp256k1 point.
    InvalidEphemeralKey,
    /// AEAD decryption failed (wrong key, flipped bit, replay with wrong key, …).
    DecryptionFailed,
}

impl std::fmt::Display for F2fCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated          => write!(f, "F2F ciphertext truncated"),
            Self::InvalidEphemeralKey => write!(f, "invalid ephemeral secp256k1 public key"),
            Self::DecryptionFailed   => write!(f, "F2F AEAD decryption failed"),
        }
    }
}

impl std::error::Error for F2fCryptoError {}

/// Encrypt `plaintext` for `recipient_pubkey`.
///
/// `recipient_pubkey` is a 33-byte compressed secp256k1 public key.
/// Returns `ephemeral_pubkey(33) || nonce(12) || ciphertext || tag(16)`.
pub fn f2f_encrypt(
    recipient_pubkey: &[u8; 33],
    plaintext: &[u8],
) -> Result<Vec<u8>, F2fCryptoError> {
    let secp = Secp256k1::new();

    // Generate ephemeral keypair using secp256k1's own OsRng (rand 0.8
    // compatible) to avoid a rand_core version mismatch.
    let (ephem_seckey, ephem_pubkey) = secp.generate_keypair(&mut SecpOsRng);

    // Parse recipient public key.
    let recip_pk = PublicKey::from_slice(recipient_pubkey)
        .map_err(|_| F2fCryptoError::InvalidEphemeralKey)?;

    // ECDH: shared point.
    let shared = SharedSecret::new(&recip_pk, &ephem_seckey);

    // KDF: BLAKE3 derive_key.
    let key_bytes = blake3::derive_key(KDF_CONTEXT, &shared.secret_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .expect("32-byte key is always valid for ChaCha20Poly1305");

    // Random 12-byte nonce via workspace rand 0.10.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt.
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|_| F2fCryptoError::DecryptionFailed)?;

    // Assemble: ephem_pk || nonce || ciphertext_with_tag.
    let mut out = Vec::with_capacity(EPHEM_PK_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&ephem_pubkey.serialize());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `f2f_encrypt` using the recipient's secret key.
///
/// `recipient_seckey` is the 32-byte raw secp256k1 secret key scalar.
pub fn f2f_decrypt(
    recipient_seckey: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, F2fCryptoError> {
    if blob.len() < OVERHEAD {
        return Err(F2fCryptoError::Truncated);
    }

    let ephem_pk_bytes: [u8; 33] = blob[..EPHEM_PK_LEN].try_into().unwrap();
    let nonce_bytes:    [u8; 12] = blob[EPHEM_PK_LEN..EPHEM_PK_LEN + NONCE_LEN].try_into().unwrap();
    let ciphertext = &blob[EPHEM_PK_LEN + NONCE_LEN..];

    let ephem_pk = PublicKey::from_slice(&ephem_pk_bytes)
        .map_err(|_| F2fCryptoError::InvalidEphemeralKey)?;
    let seckey = SecretKey::from_slice(recipient_seckey)
        .map_err(|_| F2fCryptoError::InvalidEphemeralKey)?;

    let shared = SharedSecret::new(&ephem_pk, &seckey);
    let key_bytes = blake3::derive_key(KDF_CONTEXT, &shared.secret_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .expect("32-byte key is always valid");

    let nonce = Nonce::from(nonce_bytes);
    cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| F2fCryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    fn keypair() -> ([u8; 32], [u8; 33]) {
        let secp = Secp256k1::new();
        let (sec, pub_) = secp.generate_keypair(&mut SecpOsRng);
        let sec_bytes: [u8; 32] = sec.secret_bytes().try_into().unwrap();
        let pub_bytes: [u8; 33] = pub_.serialize();
        (sec_bytes, pub_bytes)
    }

    #[test]
    fn roundtrip_empty() {
        let (sec, pub_) = keypair();
        let blob = f2f_encrypt(&pub_, b"").unwrap();
        let plain = f2f_decrypt(&sec, &blob).unwrap();
        assert_eq!(plain, b"");
    }

    #[test]
    fn roundtrip_message() {
        let (sec, pub_) = keypair();
        let msg = b"hello filament f2f encryption";
        let blob = f2f_encrypt(&pub_, msg).unwrap();
        let plain = f2f_decrypt(&sec, &blob).unwrap();
        assert_eq!(plain, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let (_sec, pub_) = keypair();
        let (wrong_sec, _) = keypair();
        let blob = f2f_encrypt(&pub_, b"secret").unwrap();
        assert_eq!(f2f_decrypt(&wrong_sec, &blob), Err(F2fCryptoError::DecryptionFailed));
    }

    #[test]
    fn truncated_fails() {
        let (sec, pub_) = keypair();
        let blob = f2f_encrypt(&pub_, b"x").unwrap();
        assert_eq!(f2f_decrypt(&sec, &blob[..10]), Err(F2fCryptoError::Truncated));
    }

    #[test]
    fn bit_flip_fails() {
        let (sec, pub_) = keypair();
        let mut blob = f2f_encrypt(&pub_, b"integrity").unwrap();
        *blob.last_mut().unwrap() ^= 0xFF;
        assert_eq!(f2f_decrypt(&sec, &blob), Err(F2fCryptoError::DecryptionFailed));
    }

    #[test]
    fn two_encryptions_differ() {
        let (_sec, pub_) = keypair();
        let b1 = f2f_encrypt(&pub_, b"same").unwrap();
        let b2 = f2f_encrypt(&pub_, b"same").unwrap();
        // Different ephemeral keys → different blobs (IND-CPA).
        assert_ne!(b1, b2);
    }
}
