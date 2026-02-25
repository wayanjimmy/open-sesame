//! Key derivation functions.
//!
//! Argon2id for password-based key derivation (OWASP recommended).

use argon2::{Algorithm, Argon2, Params, Version};

/// Derive a 32-byte AES-256 key from a password using Argon2id.
///
/// Parameters follow OWASP minimum recommendations:
/// - Algorithm: Argon2id (hybrid, resists both side-channel and GPU attacks)
/// - Memory: 19,456 KiB (19 MiB)
/// - Iterations: 2
/// - Parallelism: 1
///
/// # Errors
///
/// Returns an error if Argon2 hashing fails (should not happen with valid params).
pub fn derive_key_argon2(password: &[u8], salt: &[u8; 16]) -> core_types::Result<[u8; 32]> {
    let params = Params::new(
        19_456, // m_cost: 19 MiB
        2,      // t_cost: 2 iterations
        1,      // p_cost: 1 lane
        Some(32),
    )
    .map_err(|e| core_types::Error::Crypto(format!("argon2 params error: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| core_types::Error::Crypto(format!("argon2 derivation failed: {e}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_produces_32_byte_key() {
        let password = b"test-password";
        let salt = [0xAA; 16];
        let key = derive_key_argon2(password, &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn argon2_deterministic() {
        let password = b"deterministic";
        let salt = [0xBB; 16];
        let key1 = derive_key_argon2(password, &salt).unwrap();
        let key2 = derive_key_argon2(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn argon2_different_passwords_different_keys() {
        let salt = [0xCC; 16];
        let key1 = derive_key_argon2(b"password1", &salt).unwrap();
        let key2 = derive_key_argon2(b"password2", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2_different_salts_different_keys() {
        let password = b"same-password";
        let key1 = derive_key_argon2(password, &[0xDD; 16]).unwrap();
        let key2 = derive_key_argon2(password, &[0xEE; 16]).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn end_to_end_derive_then_encrypt() {
        let password = b"my-vault-password";
        let salt = [0xFF; 16];
        let key_bytes = derive_key_argon2(password, &salt).unwrap();

        let enc_key = crate::EncryptionKey::from_bytes(&key_bytes).unwrap();
        let nonce = [0x01; 12];
        let plaintext = b"vault secret entry";

        let ciphertext = enc_key.encrypt(&nonce, plaintext).unwrap();
        let decrypted = enc_key.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }
}
