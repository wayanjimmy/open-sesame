//! Profile schema, context-driven activation, isolation contracts, and atomic switching.
//!
//! Phase 1: schema types (`ProfileState`, `ContextSignal`, `IsolationContract`, `AuditEntry`).
//! Phase 2: runtime logic (`ContextEngine`, `AuditLogger` with BLAKE3 hash chain).
#![forbid(unsafe_code)]

pub mod context;
pub mod audit;

use core_types::{AppId, ProfileId, SensitivityClass};
use serde::{Deserialize, Serialize};

pub use context::ContextEngine;
pub use audit::{AuditLogger, verify_chain};

// ============================================================================
// Profile State Machine
// ============================================================================

/// The lifecycle state of an individual profile.
///
/// Multiple profiles may be active concurrently. Each profile has its own
/// independent state — there is no global "active profile" singleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileState {
    /// Profile is inactive (vault closed, no secrets served).
    Inactive,
    /// Profile is active (vault open, serving secrets).
    Active(ProfileId),
    /// Profile activation or deactivation is in progress.
    Transitioning(ProfileId),
}

// ============================================================================
// Context Signals
// ============================================================================

/// Signals that can trigger profile activation rule evaluation.
#[derive(Debug, Clone)]
pub enum ContextSignal {
    SsidChanged(String),
    AppFocused(AppId),
    UsbDeviceAttached(String),
    UsbDeviceDetached(String),
    HardwareKeyPresent(String),
    TimeWindowEntered(String),
    GeolocationChanged(f64, f64),
}

// ============================================================================
// Isolation Contracts
// ============================================================================

/// Defines data isolation boundaries between two profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationContract {
    pub from_profile: String,
    pub to_profile: String,
    pub resource: IsolatedResource,
    /// Condition expression evaluated at runtime (e.g. "sensitivity >= secret").
    pub condition: String,
}

/// Resources that can be isolated between profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolatedResource {
    Clipboard,
    Secrets,
    Frecency,
    Extensions,
    WindowList,
}

impl IsolationContract {
    /// Evaluate whether a cross-profile data access is permitted.
    ///
    /// Evaluates the condition expression against the given sensitivity class.
    /// Default: deny all cross-profile access (ADR-SEC-005: assume APT).
    ///
    /// Currently supports:
    /// - `"always"` → always deny (explicit strict isolation)
    /// - `"sensitivity <= public"` → allow only Public sensitivity
    /// - All other expressions → deny (fail-closed)
    #[must_use]
    pub fn permits(&self, sensitivity: SensitivityClass) -> bool {
        match self.condition.as_str() {
            "sensitivity <= public" => sensitivity == SensitivityClass::Public,
            // Fail-closed: unknown conditions deny access
            _ => false,
        }
    }
}

// ============================================================================
// Audit Log Entry
// ============================================================================

/// A hash-chained audit log entry for profile operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Wall clock timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// The profile operation that occurred.
    pub action: AuditAction,
    /// BLAKE3 hash of the previous entry (hex string). Empty for first entry.
    pub prev_hash: String,
}

/// Auditable profile actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditAction {
    ProfileActivated { target: ProfileId, duration_ms: u32 },
    ProfileDeactivated { target: ProfileId, duration_ms: u32 },
    ProfileActivationFailed { target: ProfileId, reason: String },
    DefaultProfileChanged { previous: ProfileId, current: ProfileId },
    IsolationViolationAttempt { from_profile: core_types::TrustProfileName, resource: IsolatedResource },
    SecretAccessed { profile_id: ProfileId, secret_ref: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn isolation_contract_default_denies() {
        let contract = IsolationContract {
            from_profile: "work".into(),
            to_profile: "personal".into(),
            resource: IsolatedResource::Clipboard,
            condition: "always".into(),
        };
        assert!(!contract.permits(SensitivityClass::Public));
        assert!(!contract.permits(SensitivityClass::TopSecret));
    }

    #[test]
    fn isolation_contract_public_only() {
        let contract = IsolationContract {
            from_profile: "work".into(),
            to_profile: "personal".into(),
            resource: IsolatedResource::Frecency,
            condition: "sensitivity <= public".into(),
        };
        assert!(contract.permits(SensitivityClass::Public));
        assert!(!contract.permits(SensitivityClass::Confidential));
        assert!(!contract.permits(SensitivityClass::Secret));
        assert!(!contract.permits(SensitivityClass::TopSecret));
    }

    #[test]
    fn profile_state_active() {
        let id = ProfileId::from_uuid(Uuid::from_u128(1));
        let state = ProfileState::Active(id);
        assert!(matches!(state, ProfileState::Active(_)));
    }

    #[test]
    fn audit_entry_serializes() {
        let entry = AuditEntry {
            sequence: 1,
            timestamp_ms: 1_000_000,
            action: AuditAction::ProfileActivated {
                target: ProfileId::from_uuid(Uuid::from_u128(1)),
                duration_ms: 42,
            },
            prev_hash: String::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sequence, 1);
    }

    #[test]
    fn isolated_resource_roundtrips() {
        for resource in [
            IsolatedResource::Clipboard,
            IsolatedResource::Secrets,
            IsolatedResource::Frecency,
            IsolatedResource::Extensions,
            IsolatedResource::WindowList,
        ] {
            let json = serde_json::to_string(&resource).unwrap();
            let decoded: IsolatedResource = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, resource);
        }
    }
}
