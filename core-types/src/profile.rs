use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

use crate::error::Error;
use crate::ids::ProfileId;
use crate::security::InstallationId;

// ============================================================================
// TrustProfileName — validated, path-safe trust profile identifier
// ============================================================================

/// A validated, path-safe trust profile identifier.
///
/// Invariants (enforced at construction, impossible to violate):
/// - Non-empty, max 64 bytes
/// - ASCII alphanumeric, hyphens, underscores only: `[a-zA-Z0-9][a-zA-Z0-9_-]*`
/// - Not `.` or `..` (path traversal)
/// - No whitespace, no path separators, no null bytes
///
/// Maps 1:1 to a `SQLCipher` vault file: `vaults/{name}.db`
/// Maps 1:1 to a BLAKE3 KDF context: `"pds v2 vault-key {name}"`
/// Maps 1:1 to a frecency DB: `launcher/{name}.frecency.db`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct TrustProfileName(String);

impl TrustProfileName {
    /// Validate a trust profile name. Returns a human-readable error on failure.
    fn validate(name: &str) -> std::result::Result<(), String> {
        if name.is_empty() {
            return Err("trust profile name must not be empty".into());
        }
        if name.len() > 64 {
            return Err(format!(
                "trust profile name exceeds 64 bytes (got {}): '{name}'",
                name.len()
            ));
        }
        if name == "." || name == ".." {
            return Err(format!(
                "trust profile name '{name}' is a path traversal component"
            ));
        }
        if !name.as_bytes()[0].is_ascii_alphanumeric() {
            return Err(format!(
                "trust profile name must start with alphanumeric, got '{}'",
                name.chars().next().unwrap_or('?')
            ));
        }
        for (i, b) in name.bytes().enumerate() {
            if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err(format!(
                    "trust profile name contains invalid byte 0x{b:02x} at position {i}: \
                     must contain only [a-zA-Z0-9_-]"
                ));
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for TrustProfileName {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::validate(&value).map_err(Error::Validation)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for TrustProfileName {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::validate(value).map_err(Error::Validation)?;
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for TrustProfileName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::validate(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(s))
    }
}

impl Deref for TrustProfileName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TrustProfileName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<TrustProfileName> for String {
    fn from(name: TrustProfileName) -> String {
        name.0
    }
}

// ============================================================================
// ProfileRef
// ============================================================================

/// Fully-qualified profile reference combining name, ID, and installation.
///
/// Used in federation contexts where a profile must be unambiguously identified
/// across installations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub name: TrustProfileName,
    pub id: ProfileId,
    pub installation: InstallationId,
}

// ============================================================================
// LaunchProfile — trust profile composition at launch time
// ============================================================================

/// Specifies which trust profiles to stack when launching an application.
///
/// Trust profiles compose: launching with `[corporate-aws, local, azure-client]`
/// means the process gets secrets from all three, with precedence determined
/// by list ordering (last = highest priority).
///
/// Not fully implemented yet — currently used as single `TrustProfileName`
/// via `LaunchProfile::single()`. The struct exists so trust profile stacking
/// is an additive change, not a rewrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchProfile {
    /// Trust profiles to compose. Ordered by precedence: last = highest priority.
    pub trust_profiles: Vec<TrustProfileName>,
    /// How to handle secret key conflicts across stacked profiles.
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,
}

impl LaunchProfile {
    /// Create a launch profile with a single trust profile (current usage).
    #[must_use]
    pub fn single(name: TrustProfileName) -> Self {
        Self {
            trust_profiles: vec![name],
            conflict_policy: ConflictPolicy::default(),
        }
    }
}

/// How to resolve secret key conflicts when multiple trust profiles are stacked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictPolicy {
    /// Abort with actionable error, no secret leakage.
    #[default]
    Strict,
    /// Log warning, higher-precedence (later in list) wins.
    Warn,
    /// Silently use higher-precedence value.
    Last,
}
