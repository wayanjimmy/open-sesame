//! Password-wrap blob: AES-256-GCM wrapped master key under Argon2id-derived KEK.
//!
//! Binary format:
//! ```text
//! Version byte (1 byte): 0x01
//! Nonce (12 bytes): random
//! Ciphertext + GCM tag (48 bytes): AES-256-GCM(Argon2id(password, salt), master_key)
//! ```
//!
//! Total: 61 bytes.
//!
//! The KEK is `Argon2id(password, salt)` — the same KDF used previously to
//! derive the master key directly. In multi-factor mode, however, the master
//! key is random (`getrandom(32)`) and the Argon2id output wraps it rather
//! than being it.

use crate::AuthError;
use zeroize::Zeroize;

/// Version of the password-wrap blob format.
pub const PASSWORD_WRAP_VERSION: u8 = 0x01;

/// Expected ciphertext length: 32-byte master key + 16-byte GCM tag.
const CIPHERTEXT_LEN: usize = 48;

/// Total blob size: 1 (version) + 12 (nonce) + 48 (ciphertext).
const BLOB_LEN: usize = 1 + 12 + CIPHERTEXT_LEN;

/// Parsed password-wrap blob.
pub struct PasswordWrapBlob {
    pub version: u8,
    pub nonce: [u8; 12],
    /// 32 bytes master key + 16 bytes GCM tag = 48 bytes.
    pub ciphertext: Vec<u8>,
}

impl Drop for PasswordWrapBlob {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

impl PasswordWrapBlob {
    /// Serialize to the binary format.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(BLOB_LEN);
        buf.push(self.version);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from the binary format.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidBlob` if the data is truncated or has an
    /// unsupported version.
    pub fn deserialize(data: &[u8]) -> Result<Self, AuthError> {
        if data.len() < BLOB_LEN {
            return Err(AuthError::InvalidBlob(format!(
                "password-wrap blob too short: {} bytes, expected {BLOB_LEN}",
                data.len()
            )));
        }

        let version = data[0];
        if version != PASSWORD_WRAP_VERSION {
            return Err(AuthError::InvalidBlob(format!(
                "unsupported password-wrap version {version:#04x}, expected {PASSWORD_WRAP_VERSION:#04x}"
            )));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[1..13]);

        let ciphertext = data[13..13 + CIPHERTEXT_LEN].to_vec();

        Ok(Self {
            version,
            nonce,
            ciphertext,
        })
    }

    /// Create a new blob by wrapping a master key under a password-derived KEK.
    ///
    /// `kek_bytes` must be 32 bytes (the Argon2id output). Zeroized after use.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails or random nonce generation fails.
    pub fn wrap(master_key: &[u8], kek_bytes: &mut [u8; 32]) -> Result<Self, AuthError> {
        let encryption_key = core_crypto::EncryptionKey::from_bytes(kek_bytes)
            .map_err(|_| AuthError::UnwrapFailed)?;

        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| AuthError::Io(std::io::Error::other(e)))?;

        let ciphertext = encryption_key
            .encrypt(&nonce, master_key)
            .map_err(|_| AuthError::UnwrapFailed)?;

        kek_bytes.zeroize();

        Ok(Self {
            version: PASSWORD_WRAP_VERSION,
            nonce,
            ciphertext,
        })
    }

    /// Unwrap the master key using a password-derived KEK.
    ///
    /// `kek_bytes` must be 32 bytes (the Argon2id output). Zeroized after use.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::UnwrapFailed` if the KEK is wrong (GCM auth fails).
    pub fn unwrap(&self, kek_bytes: &mut [u8; 32]) -> Result<core_crypto::SecureBytes, AuthError> {
        let encryption_key = core_crypto::EncryptionKey::from_bytes(kek_bytes)
            .map_err(|_| AuthError::UnwrapFailed)?;
        kek_bytes.zeroize();

        encryption_key
            .decrypt(&self.nonce, &self.ciphertext)
            .map_err(|_| AuthError::UnwrapFailed)
    }

    /// Path to the password-wrap blob for a profile.
    #[must_use]
    pub fn path(
        config_dir: &std::path::Path,
        profile: &core_types::TrustProfileName,
    ) -> std::path::PathBuf {
        config_dir
            .join("vaults")
            .join(format!("{profile}.password-wrap"))
    }

    /// Read blob from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist or is corrupt.
    pub fn load(
        config_dir: &std::path::Path,
        profile: &core_types::TrustProfileName,
    ) -> Result<Self, AuthError> {
        let path = Self::path(config_dir, profile);
        let data = std::fs::read(&path).map_err(|e| {
            AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read password-wrap blob {}: {e}", path.display()),
            ))
        })?;
        Self::deserialize(&data)
    }

    /// Write blob to disk atomically with restrictive permissions.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the write fails.
    pub fn save(
        &self,
        config_dir: &std::path::Path,
        profile: &core_types::TrustProfileName,
    ) -> Result<(), AuthError> {
        let path = Self::path(config_dir, profile);
        let vaults_dir = config_dir.join("vaults");
        std::fs::create_dir_all(&vaults_dir)?;

        let tmp_path = path.with_extension("password-wrap.tmp");
        std::fs::write(&tmp_path, self.serialize())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialize() {
        let blob = PasswordWrapBlob {
            version: PASSWORD_WRAP_VERSION,
            nonce: [0xAA; 12],
            ciphertext: vec![0xBB; CIPHERTEXT_LEN],
        };

        let data = blob.serialize();
        assert_eq!(data.len(), BLOB_LEN);

        let parsed = PasswordWrapBlob::deserialize(&data).unwrap();
        assert_eq!(parsed.version, PASSWORD_WRAP_VERSION);
        assert_eq!(parsed.nonce, [0xAA; 12]);
        assert_eq!(parsed.ciphertext.len(), CIPHERTEXT_LEN);
    }

    #[test]
    fn rejects_truncated() {
        let result = PasswordWrapBlob::deserialize(&[0x01; 10]);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut data = vec![0xFF];
        data.extend_from_slice(&[0u8; 12 + CIPHERTEXT_LEN]);
        let result = PasswordWrapBlob::deserialize(&data);
        assert!(matches!(result, Err(AuthError::InvalidBlob(_))));
    }

    #[test]
    fn wrap_and_unwrap_round_trip() {
        let master_key = [0x42u8; 32];
        let mut kek = [0xDE; 32];

        let blob = PasswordWrapBlob::wrap(&master_key, &mut kek).unwrap();
        // KEK should be zeroized after wrap.
        assert_eq!(kek, [0u8; 32]);

        // Re-derive KEK for unwrap.
        let mut kek2 = [0xDE; 32];
        let unwrapped = blob.unwrap(&mut kek2).unwrap();
        assert_eq!(unwrapped.as_bytes(), &master_key);
        // KEK should be zeroized after unwrap.
        assert_eq!(kek2, [0u8; 32]);
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let master_key = [0x42u8; 32];
        let mut kek = [0xDE; 32];

        let blob = PasswordWrapBlob::wrap(&master_key, &mut kek).unwrap();

        let mut wrong_kek = [0xAB; 32];
        let result = blob.unwrap(&mut wrong_kek);
        assert!(matches!(result, Err(AuthError::UnwrapFailed)));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = core_types::TrustProfileName::try_from("test-profile").unwrap();

        let master_key = [0x42u8; 32];
        let mut kek = [0xDE; 32];
        let blob = PasswordWrapBlob::wrap(&master_key, &mut kek).unwrap();

        blob.save(dir.path(), &profile).unwrap();
        let loaded = PasswordWrapBlob::load(dir.path(), &profile).unwrap();

        let mut kek2 = [0xDE; 32];
        let unwrapped = loaded.unwrap(&mut kek2).unwrap();
        assert_eq!(unwrapped.as_bytes(), &master_key);
    }

    #[test]
    fn file_permissions_are_restrictive() {
        let dir = tempfile::tempdir().unwrap();
        let profile = core_types::TrustProfileName::try_from("test-profile").unwrap();

        let blob = PasswordWrapBlob {
            version: PASSWORD_WRAP_VERSION,
            nonce: [0; 12],
            ciphertext: vec![0; CIPHERTEXT_LEN],
        };
        blob.save(dir.path(), &profile).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = PasswordWrapBlob::path(dir.path(), &profile);
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }
}
