//! Vault metadata: tracks enrolled factors, auth policy, and init mode.
//!
//! Stored as JSON at `{config_dir}/vaults/{profile}.vault-meta`.
//! JSON is used (not TOML) to distinguish machine-managed metadata from
//! user-editable configuration.

use crate::AuthError;
use core_types::{AuthCombineMode, AuthFactorId};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Current metadata format version.
pub const VAULT_META_VERSION: u32 = 1;

/// Maximum metadata version this code can read.
pub const MAX_SUPPORTED_VERSION: u32 = 1;

/// Persistent metadata for a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Metadata format version.
    pub version: u32,
    /// How this vault was initialized.
    pub init_mode: VaultInitMode,
    /// Which auth methods are enrolled.
    pub enrolled_factors: Vec<EnrolledFactor>,
    /// The unlock policy for this vault.
    pub auth_policy: AuthCombineMode,
    /// Timestamp of vault creation (Unix epoch seconds).
    pub created_at: u64,
    /// Timestamp of last policy change.
    pub policy_changed_at: u64,
}

/// How the vault was originally initialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultInitMode {
    /// Initialized with password only.
    Password,
    /// Initialized with SSH key only (random master key, no password).
    SshKeyOnly,
    /// Initialized with multiple factors.
    MultiFactor {
        /// The factors used at init time.
        factors: Vec<AuthFactorId>,
    },
}

/// Record of an enrolled authentication factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledFactor {
    /// Which factor type.
    pub factor_id: AuthFactorId,
    /// Human-readable label (e.g., SSH key fingerprint, "master password").
    pub label: String,
    /// When this factor was enrolled (Unix epoch seconds).
    pub enrolled_at: u64,
}

/// Get the current Unix epoch timestamp.
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl VaultMetadata {
    /// Path to the metadata file for a profile.
    #[must_use]
    pub fn path(config_dir: &Path, profile: &core_types::TrustProfileName) -> PathBuf {
        config_dir
            .join("vaults")
            .join(format!("{profile}.vault-meta"))
    }

    /// Read metadata from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, is unreadable, unparseable,
    /// or has an unsupported version.
    pub fn load(
        config_dir: &Path,
        profile: &core_types::TrustProfileName,
    ) -> Result<Self, AuthError> {
        let path = Self::path(config_dir, profile);
        let data = std::fs::read_to_string(&path).map_err(|e| {
            AuthError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read vault metadata {}: {e}", path.display()),
            ))
        })?;
        let meta: Self = serde_json::from_str(&data).map_err(|e| {
            AuthError::InvalidBlob(format!("corrupt vault metadata {}: {e}", path.display()))
        })?;
        if meta.version > MAX_SUPPORTED_VERSION {
            return Err(AuthError::InvalidBlob(format!(
                "vault metadata version {} exceeds max supported {}",
                meta.version, MAX_SUPPORTED_VERSION
            )));
        }
        Ok(meta)
    }

    /// Write metadata to disk atomically.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the write fails.
    pub fn save(
        &self,
        config_dir: &Path,
        profile: &core_types::TrustProfileName,
    ) -> Result<(), AuthError> {
        let path = Self::path(config_dir, profile);
        let vaults_dir = config_dir.join("vaults");
        std::fs::create_dir_all(&vaults_dir)?;

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AuthError::InvalidBlob(format!("failed to serialize vault metadata: {e}"))
        })?;

        let tmp_path = path.with_extension("vault-meta.tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Create metadata for a new password-only vault.
    #[must_use]
    pub fn new_password(auth_policy: AuthCombineMode) -> Self {
        let now = now_epoch();
        Self {
            version: VAULT_META_VERSION,
            init_mode: VaultInitMode::Password,
            enrolled_factors: vec![EnrolledFactor {
                factor_id: AuthFactorId::Password,
                label: "master password".into(),
                enrolled_at: now,
            }],
            auth_policy,
            created_at: now,
            policy_changed_at: now,
        }
    }

    /// Create metadata for a new SSH-key-only vault.
    #[must_use]
    pub fn new_ssh_only(fingerprint: &str, auth_policy: AuthCombineMode) -> Self {
        let now = now_epoch();
        Self {
            version: VAULT_META_VERSION,
            init_mode: VaultInitMode::SshKeyOnly,
            enrolled_factors: vec![EnrolledFactor {
                factor_id: AuthFactorId::SshAgent,
                label: fingerprint.to_string(),
                enrolled_at: now,
            }],
            auth_policy,
            created_at: now,
            policy_changed_at: now,
        }
    }

    /// Create metadata for a new multi-factor vault.
    #[must_use]
    pub fn new_multi_factor(factors: Vec<EnrolledFactor>, auth_policy: AuthCombineMode) -> Self {
        let now = now_epoch();
        let factor_ids: Vec<AuthFactorId> = factors.iter().map(|f| f.factor_id).collect();
        Self {
            version: VAULT_META_VERSION,
            init_mode: VaultInitMode::MultiFactor {
                factors: factor_ids,
            },
            enrolled_factors: factors,
            auth_policy,
            created_at: now,
            policy_changed_at: now,
        }
    }

    /// Check whether a specific factor is enrolled.
    #[must_use]
    pub fn has_factor(&self, factor: AuthFactorId) -> bool {
        self.enrolled_factors.iter().any(|f| f.factor_id == factor)
    }

    /// Add an enrolled factor. Does nothing if already enrolled with the same ID.
    pub fn add_factor(&mut self, factor_id: AuthFactorId, label: String) {
        if self.has_factor(factor_id) {
            return;
        }
        self.enrolled_factors.push(EnrolledFactor {
            factor_id,
            label,
            enrolled_at: now_epoch(),
        });
    }

    /// Remove an enrolled factor by ID.
    pub fn remove_factor(&mut self, factor_id: AuthFactorId) {
        self.enrolled_factors.retain(|f| f.factor_id != factor_id);
    }

    /// What kind of contribution each factor makes under this vault's policy.
    #[must_use]
    pub fn contribution_type(&self) -> crate::FactorContribution {
        match self.auth_policy {
            AuthCombineMode::All => crate::FactorContribution::FactorPiece,
            AuthCombineMode::Any | AuthCombineMode::Policy(_) => {
                crate::FactorContribution::CompleteMasterKey
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::TrustProfileName;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[test]
    fn load_fails_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = VaultMetadata::load(dir.path(), &test_profile());
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();

        let meta = VaultMetadata::new_password(AuthCombineMode::Any);

        meta.save(dir.path(), &profile).unwrap();
        let loaded = VaultMetadata::load(dir.path(), &profile).unwrap();

        assert_eq!(loaded.version, VAULT_META_VERSION);
        assert_eq!(loaded.enrolled_factors.len(), 1);
        assert_eq!(loaded.enrolled_factors[0].factor_id, AuthFactorId::Password);
        assert_eq!(loaded.auth_policy, AuthCombineMode::Any);
    }

    #[test]
    fn rejects_unsupported_version() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        let path = vaults.join("test-profile.vault-meta");
        let json = r#"{"version":999,"init_mode":"password","enrolled_factors":[],"auth_policy":"any","created_at":0,"policy_changed_at":0}"#;
        std::fs::write(&path, json).unwrap();

        let result = VaultMetadata::load(dir.path(), &profile);
        assert!(result.is_err());
    }

    #[test]
    fn new_password_creates_correct_metadata() {
        let meta = VaultMetadata::new_password(AuthCombineMode::Any);
        assert_eq!(meta.enrolled_factors.len(), 1);
        assert_eq!(meta.enrolled_factors[0].factor_id, AuthFactorId::Password);
        assert!(matches!(meta.init_mode, VaultInitMode::Password));
        assert_eq!(meta.auth_policy, AuthCombineMode::Any);
    }

    #[test]
    fn new_ssh_only_creates_correct_metadata() {
        let meta = VaultMetadata::new_ssh_only("SHA256:test", AuthCombineMode::Any);
        assert_eq!(meta.enrolled_factors.len(), 1);
        assert_eq!(meta.enrolled_factors[0].factor_id, AuthFactorId::SshAgent);
        assert_eq!(meta.enrolled_factors[0].label, "SHA256:test");
        assert!(matches!(meta.init_mode, VaultInitMode::SshKeyOnly));
    }

    #[test]
    fn new_multi_factor_creates_correct_metadata() {
        let factors = vec![
            EnrolledFactor {
                factor_id: AuthFactorId::Password,
                label: "master password".into(),
                enrolled_at: 0,
            },
            EnrolledFactor {
                factor_id: AuthFactorId::SshAgent,
                label: "SHA256:abc".into(),
                enrolled_at: 0,
            },
        ];
        let meta = VaultMetadata::new_multi_factor(factors, AuthCombineMode::All);
        assert_eq!(meta.enrolled_factors.len(), 2);
        assert!(matches!(meta.init_mode, VaultInitMode::MultiFactor { .. }));
        assert_eq!(meta.auth_policy, AuthCombineMode::All);
    }

    #[test]
    fn has_factor_works() {
        let meta = VaultMetadata::new_password(AuthCombineMode::Any);
        assert!(meta.has_factor(AuthFactorId::Password));
        assert!(!meta.has_factor(AuthFactorId::SshAgent));
    }

    #[test]
    fn add_factor_idempotent() {
        let mut meta = VaultMetadata::new_password(AuthCombineMode::Any);

        meta.add_factor(AuthFactorId::Password, "duplicate".into());
        assert_eq!(meta.enrolled_factors.len(), 1);

        meta.add_factor(AuthFactorId::SshAgent, "SHA256:abc".into());
        assert_eq!(meta.enrolled_factors.len(), 2);
    }

    #[test]
    fn remove_factor_works() {
        let mut meta = VaultMetadata::new_password(AuthCombineMode::Any);
        meta.add_factor(AuthFactorId::SshAgent, "ssh".into());
        assert_eq!(meta.enrolled_factors.len(), 2);

        meta.remove_factor(AuthFactorId::SshAgent);
        assert_eq!(meta.enrolled_factors.len(), 1);
        assert!(!meta.has_factor(AuthFactorId::SshAgent));
    }

    #[test]
    fn policy_mode_serializes_correctly() {
        let meta = VaultMetadata::new_multi_factor(
            vec![],
            AuthCombineMode::Policy(core_types::AuthPolicy {
                required: vec![AuthFactorId::Password],
                additional_required: 1,
            }),
        );

        let json = serde_json::to_string(&meta).unwrap();
        let parsed: VaultMetadata = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.auth_policy, AuthCombineMode::Policy(_)));
    }

    #[test]
    fn file_permissions_are_restrictive() {
        let dir = tempfile::tempdir().unwrap();
        let profile = test_profile();

        let meta = VaultMetadata::new_password(AuthCombineMode::Any);
        meta.save(dir.path(), &profile).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = VaultMetadata::path(dir.path(), &profile);
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }
}
