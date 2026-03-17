//! Authentication backend dispatcher.
//!
//! Dispatches vault unlock across registered authentication backends.
//! Tries non-interactive backends first, falling back to password entry
//! when no automatic method is available.

use crate::backend::{AuthInteraction, VaultAuthBackend};
use crate::password::PasswordBackend;
use crate::ssh::SshAgentBackend;
use crate::vault_meta::VaultMetadata;
use core_types::{AuthCombineMode, TrustProfileName};
use std::path::Path;

/// Dispatches vault unlock across registered authentication backends.
///
/// Backend priority order:
/// 1. SSH-agent (non-interactive, if enrolled and agent available)
/// 2. Password (interactive fallback)
pub struct AuthDispatcher {
    backends: Vec<Box<dyn VaultAuthBackend>>,
}

impl AuthDispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: vec![
                Box::new(SshAgentBackend::new()),
                Box::new(PasswordBackend::new()),
            ],
        }
    }

    /// Access all registered backends.
    #[must_use]
    pub fn backends(&self) -> &[Box<dyn VaultAuthBackend>] {
        &self.backends
    }

    /// Determine which backends are applicable for a vault given its metadata.
    ///
    /// A backend is applicable if it is enrolled in the vault metadata AND
    /// can currently perform an unlock.
    pub async fn applicable_backends(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        meta: &VaultMetadata,
    ) -> Vec<&dyn VaultAuthBackend> {
        let mut applicable = Vec::new();
        for backend in &self.backends {
            if meta.has_factor(backend.factor_id()) && backend.can_unlock(profile, config_dir).await
            {
                applicable.push(backend.as_ref());
            }
        }
        applicable
    }

    /// Find the first non-interactive backend that is enrolled AND available.
    pub async fn find_auto_backend(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
    ) -> Option<&dyn VaultAuthBackend> {
        for backend in &self.backends {
            if backend.requires_interaction() == AuthInteraction::None
                && backend.is_enrolled(profile, config_dir)
                && backend.can_unlock(profile, config_dir).await
            {
                return Some(backend.as_ref());
            }
        }
        None
    }

    /// Determine if all required factors for a policy can be satisfied
    /// without interaction (auto-unlock feasibility check).
    pub async fn can_auto_unlock(
        &self,
        profile: &TrustProfileName,
        config_dir: &Path,
        meta: &VaultMetadata,
    ) -> bool {
        match &meta.auth_policy {
            AuthCombineMode::Any => {
                // Any single non-interactive backend suffices.
                self.find_auto_backend(profile, config_dir).await.is_some()
            }
            AuthCombineMode::All | AuthCombineMode::Policy(_) => {
                // All required factors must be non-interactive.
                // Conservative: return false if any required factor needs interaction.
                let applicable = self.applicable_backends(profile, config_dir, meta).await;
                if applicable.is_empty() {
                    return false;
                }
                applicable
                    .iter()
                    .all(|b| b.requires_interaction() == AuthInteraction::None)
            }
        }
    }

    /// Get the password backend (always available as fallback).
    ///
    /// # Panics
    ///
    /// Panics if the password backend was not registered (this is a programming
    /// error — the constructor always registers it).
    #[must_use]
    pub fn password_backend(&self) -> &dyn VaultAuthBackend {
        self.backends
            .iter()
            .find(|b| b.backend_id() == "password")
            .map(std::convert::AsRef::as_ref)
            .expect("password backend is always registered")
    }
}

impl Default for AuthDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> TrustProfileName {
        TrustProfileName::try_from("test-profile").unwrap()
    }

    #[tokio::test]
    async fn find_auto_backend_returns_none_without_enrollment() {
        let dispatcher = AuthDispatcher::new();
        let profile = test_profile();
        let result = dispatcher
            .find_auto_backend(&profile, std::path::Path::new("/nonexistent"))
            .await;
        assert!(result.is_none());
    }

    #[test]
    fn password_backend_always_available() {
        let dispatcher = AuthDispatcher::new();
        let backend = dispatcher.password_backend();
        assert_eq!(backend.backend_id(), "password");
        assert_eq!(
            backend.requires_interaction(),
            AuthInteraction::PasswordEntry
        );
    }

    #[tokio::test]
    async fn applicable_backends_empty_when_no_enrollment() {
        let dispatcher = AuthDispatcher::new();
        let profile = test_profile();
        let meta = VaultMetadata::new_password(AuthCombineMode::Any);
        // PasswordBackend.can_unlock requires .password-wrap file to exist.
        let applicable = dispatcher
            .applicable_backends(&profile, std::path::Path::new("/nonexistent"), &meta)
            .await;
        // Password has no .password-wrap at /nonexistent, so it's not applicable.
        assert!(applicable.is_empty());
    }

    #[tokio::test]
    async fn can_auto_unlock_false_without_enrollment() {
        let dispatcher = AuthDispatcher::new();
        let profile = test_profile();
        let meta = VaultMetadata::new_password(AuthCombineMode::Any);
        assert!(
            !dispatcher
                .can_auto_unlock(&profile, std::path::Path::new("/nonexistent"), &meta)
                .await
        );
    }
}
