use serde::{Deserialize, Serialize};

use crate::profile::TrustProfileName;

/// Why an unlock request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockRejectedReason {
    /// System is already unlocked. Distinct from wrong password.
    AlreadyUnlocked,
}

/// Why a secret operation was denied (typed denial, replaces ambiguous empty responses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecretDenialReason {
    Locked,
    ProfileNotActive,
    AccessDenied,
    RateLimited,
    NotFound,
    VaultError(String),
}

/// Why a launch was denied. Machine-readable so the WM can take action
/// (e.g. prompt for vault unlock when `VaultsLocked`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LaunchDenial {
    /// One or more required vaults are locked. The WM can offer inline unlock.
    VaultsLocked {
        locked_profiles: Vec<TrustProfileName>,
    },
    /// Required secrets were not found (configuration error, not lock state).
    /// Count is opaque to avoid revealing which secrets exist.
    SecretNotFound { missing_count: u32 },
    /// Rate limiting on secret access.
    RateLimited,
    /// A trust profile referenced by a tag does not exist in config.
    ProfileNotFound { profile: String },
    /// A launch profile referenced by a tag does not exist.
    LaunchProfileNotFound {
        profile: String,
        launch_profile: String,
    },
    /// Desktop entry not found in the launcher cache.
    EntryNotFound,
    /// The spawned process failed to start.
    SpawnFailed { reason: String },
}
