//! Profile schema, context-driven activation, isolation contracts, and atomic switching.
//!
//! Phase 1 scope: schema types only. Runtime logic (context engine, switch
//! transaction, audit logging) is deferred to Phase 2.
#![forbid(unsafe_code)]

use core_types::{AppId, ProfileId, SensitivityClass};
use serde::{Deserialize, Serialize};

// ============================================================================
// Profile State Machine
// ============================================================================

/// The lifecycle state of the profile system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileState {
    /// A profile is active and stable.
    Active(ProfileId),
    /// A profile switch is in progress.
    Switching {
        from: ProfileId,
        to: ProfileId,
    },
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
    /// Phase 1: always denies (strict isolation by default).
    /// Phase 2: evaluates the condition expression.
    #[must_use]
    pub fn permits(&self, _sensitivity: SensitivityClass) -> bool {
        false
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
    /// SHA-256 hash of the previous entry (hex string). Empty for first entry.
    pub prev_hash: String,
}

/// Auditable profile actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditAction {
    ProfileSwitched { from: ProfileId, to: ProfileId, duration_ms: u32 },
    ProfileSwitchFailed { from: ProfileId, to: ProfileId, reason: String },
    IsolationViolationAttempt { from_profile: String, resource: IsolatedResource },
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
            action: AuditAction::ProfileSwitched {
                from: ProfileId::from_uuid(Uuid::from_u128(1)),
                to: ProfileId::from_uuid(Uuid::from_u128(2)),
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
