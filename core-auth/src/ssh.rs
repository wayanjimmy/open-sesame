//! SSH-agent authentication backend (stub).
//!
//! Checks for enrollment blob existence but does not perform actual
//! SSH-agent socket communication. The signing, KEK derivation, and
//! master key unwrapping protocol is defined but not yet wired.

use crate::backend::{AuthInteraction, UnlockOutcome, VaultAuthBackend};
use crate::AuthError;
use core_crypto::SecureBytes;
use core_types::TrustProfileName;
use std::path::Path;

/// SSH-agent backed vault authentication (stub).
///
/// When fully implemented, this backend will:
/// 1. Connect to `$SSH_AUTH_SOCK`
/// 2. Sign a BLAKE3-derived challenge with the enrolled key
/// 3. Derive a KEK from the signature
/// 4. Unwrap the master key from the enrollment blob
/// 5. Send the master key via `SshUnlockRequest`
pub struct SshAgentBackend;

impl SshAgentBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Path to the enrollment blob for a profile.
    fn enrollment_path(config_dir: &Path, profile: &TrustProfileName) -> std::path::PathBuf {
        config_dir
            .join("vaults")
            .join(format!("{profile}.ssh-enrollment"))
    }
}

impl Default for SshAgentBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl VaultAuthBackend for SshAgentBackend {
    fn name(&self) -> &str {
        "SSH Agent"
    }

    fn backend_id(&self) -> &str {
        "ssh-agent"
    }

    fn is_enrolled(&self, profile: &TrustProfileName, config_dir: &Path) -> bool {
        Self::enrollment_path(config_dir, profile).exists()
    }

    async fn can_unlock(&self, _profile: &TrustProfileName, _config_dir: &Path) -> bool {
        // Stub: no agent communication yet.
        false
    }

    fn requires_interaction(&self) -> AuthInteraction {
        AuthInteraction::None
    }

    async fn unlock(
        &self,
        _profile: &TrustProfileName,
        _config_dir: &Path,
        _salt: &[u8],
    ) -> Result<UnlockOutcome, AuthError> {
        Err(AuthError::AgentUnavailable(
            "SSH agent backend not yet implemented".into(),
        ))
    }

    async fn enroll(
        &self,
        _profile: &TrustProfileName,
        _master_key: &SecureBytes,
        _config_dir: &Path,
        _salt: &[u8],
    ) -> Result<(), AuthError> {
        Err(AuthError::BackendNotApplicable(
            "SSH agent enrollment not yet implemented".into(),
        ))
    }

    async fn revoke(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
    ) -> Result<(), AuthError> {
        let path = Self::enrollment_path(config_dir, profile);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[test]
    fn is_enrolled_checks_file() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        assert!(!backend.is_enrolled(&profile, dir.path()));

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        std::fs::write(vaults.join("test-profile.ssh-enrollment"), b"blob").unwrap();

        assert!(backend.is_enrolled(&profile, dir.path()));
    }

    #[tokio::test]
    async fn can_unlock_returns_false() {
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        assert!(!backend.can_unlock(&profile, std::path::Path::new("/tmp")).await);
    }

    #[tokio::test]
    async fn unlock_returns_agent_unavailable() {
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        let result = backend.unlock(&profile, std::path::Path::new("/tmp"), &[0; 16]).await;
        assert!(matches!(result, Err(AuthError::AgentUnavailable(_))));
    }

    #[tokio::test]
    async fn revoke_removes_blob() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();

        let vaults = dir.path().join("vaults");
        std::fs::create_dir_all(&vaults).unwrap();
        let blob_path = vaults.join("test-profile.ssh-enrollment");
        std::fs::write(&blob_path, b"blob").unwrap();
        assert!(blob_path.exists());

        backend.revoke(&profile, dir.path()).await.unwrap();
        assert!(!blob_path.exists());
    }

    #[tokio::test]
    async fn revoke_noop_when_no_blob() {
        let dir = tempfile::tempdir().unwrap();
        let backend = SshAgentBackend::new();
        let profile = test_profile();
        backend.revoke(&profile, dir.path()).await.unwrap();
    }

    #[test]
    fn requires_no_interaction() {
        let backend = SshAgentBackend::new();
        assert_eq!(backend.requires_interaction(), AuthInteraction::None);
    }

    #[test]
    fn backend_id_is_ssh_agent() {
        let backend = SshAgentBackend::new();
        assert_eq!(backend.backend_id(), "ssh-agent");
    }
}
