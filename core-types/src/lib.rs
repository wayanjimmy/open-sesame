//! Shared types, error types, and event schema for the PDS IPC bus.
//!
//! This crate defines the canonical type system shared across all PDS crates.
//! It has zero platform dependencies and is `no_std`-compatible for hot-path types.
//! Minimal external deps: serde, uuid, thiserror.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

// ============================================================================
// Identity Types
// ============================================================================

macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", $prefix, self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_id!(ProfileId, "prof");
define_id!(WindowId, "win");
define_id!(WorkspaceId, "ws");
define_id!(MonitorId, "mon");
define_id!(ClipboardEntryId, "clip");
define_id!(DaemonId, "dmon");
define_id!(ExtensionId, "ext");

// ============================================================================
// AppId
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(String);

impl AppId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Extract the last segment of a reverse-DNS app ID.
    /// `"com.mitchellh.ghostty"` -> `"ghostty"`
    /// `"firefox"` -> `"firefox"`
    #[must_use]
    pub fn last_segment(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive match against another `AppId` or fragment.
    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
            || self.last_segment().eq_ignore_ascii_case(other)
            || other
                .rsplit('.')
                .next()
                .is_some_and(|seg| self.last_segment().eq_ignore_ascii_case(seg))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// SecretRef
// ============================================================================

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretRef {
    /// Profile-scoped keyring: `{ secret = "work/github-token" }`
    Keyring { secret: String },
    /// 1Password CLI: `{ op = "op://Private/OpenAI/api-key" }`
    OnePassword { op: String },
    /// Environment variable (CI only): `{ env = "DB_PASSWORD" }`
    Env { env: String },
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyring { secret } => write!(f, "SecretRef(keyring:{secret})"),
            Self::OnePassword { op } => write!(f, "SecretRef(op:{op})"),
            Self::Env { env } => write!(f, "SecretRef(env:{env})"),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ============================================================================
// SensitivityClass
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensitivityClass {
    Public,
    Confidential,
    Secret,
    TopSecret,
}

impl Default for SensitivityClass {
    fn default() -> Self {
        Self::Public
    }
}

// ============================================================================
// SecurityLevel
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    /// Events visible to all subscribers including extensions.
    Open,
    /// Events visible to authenticated daemons only.
    Internal,
    /// Events visible only to daemons holding the current profile's security context.
    ProfileScoped,
    /// Events visible only to the secrets daemon.
    SecretsOnly,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Internal
    }
}

// ============================================================================
// Timestamp
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    /// Monotonic counter for ordering within a single daemon lifecycle.
    /// Nanoseconds since daemon start.
    pub monotonic_ns: u64,
    /// Wall clock for cross-daemon and cross-restart ordering.
    /// Milliseconds since Unix epoch.
    pub wall_ms: u64,
}

impl Timestamp {
    #[must_use]
    pub fn now(epoch: Instant) -> Self {
        let mono = epoch.elapsed();
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self {
            monotonic_ns: mono.as_nanos() as u64,
            wall_ms: wall.as_millis() as u64,
        }
    }
}

// ============================================================================
// EventKind
// ============================================================================

/// Externally-tagged enum (serde default) for postcard wire compatibility.
/// Postcard does not support `#[serde(tag = "...", content = "...")]`.
/// JSON output uses `{"VariantName": {...}}` format which is still
/// fully deserializable and forward-compatible via `#[serde(other)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    // -- Window Manager Events --
    WindowFocused {
        window_id: WindowId,
        app_id: AppId,
        workspace_id: WorkspaceId,
    },
    WindowMoved {
        window_id: WindowId,
        from_workspace: WorkspaceId,
        to_workspace: WorkspaceId,
    },
    WorkspaceSwitched {
        from: WorkspaceId,
        to: WorkspaceId,
        monitor_id: MonitorId,
    },
    LayoutChanged {
        workspace_id: WorkspaceId,
        layout_name: String,
    },

    // -- Profile Events --
    ProfileSwitchRequested {
        from: ProfileId,
        to: ProfileId,
        trigger: String,
    },
    ProfileSwitchBegun {
        from: ProfileId,
        to: ProfileId,
    },
    ProfileSwitched {
        from: ProfileId,
        to: ProfileId,
        duration_ms: u32,
    },
    ContextChanged {
        changed_signals: Vec<String>,
    },

    // -- Clipboard Events --
    ClipboardChanged {
        entry_id: ClipboardEntryId,
        sensitivity: SensitivityClass,
        content_type: String,
        profile_id: ProfileId,
    },
    ClipboardEntryExpired {
        entry_id: ClipboardEntryId,
    },
    ClipboardScopeSealed {
        profile_id: ProfileId,
    },

    // -- Input Events --
    HotkeyFired {
        sequence: String,
        layer: String,
        action: String,
    },
    LayerChanged {
        from: String,
        to: String,
        trigger_app: Option<AppId>,
    },
    MacroTriggered {
        macro_id: String,
        expansion_preview: String,
    },

    // -- Secrets Events (authorized daemons only) --
    SecretResolved {
        secret_ref: String,
        ttl_remaining_s: u32,
    },
    SecretExpired {
        secret_ref: String,
    },
    SsoSessionExpired {
        profile_id: ProfileId,
        provider: String,
    },

    // -- Launcher Events --
    AppLaunched {
        app_id: AppId,
        launch_action: String,
        profile_id: ProfileId,
    },
    QuerySubmitted {
        query: String,
        result_count: u32,
        latency_ms: u32,
    },

    // -- System Events --
    DaemonStarted {
        daemon_id: DaemonId,
        version: String,
        capabilities: Vec<String>,
    },
    DaemonStopped {
        daemon_id: DaemonId,
        reason: String,
    },
    ConfigReloaded {
        daemon_id: DaemonId,
        changed_keys: Vec<String>,
    },
    PolicyApplied {
        source: String,
        locked_keys: Vec<String>,
    },

    // Forward compatibility: unknown events deserialize to this variant.
    #[serde(other)]
    Unknown,
}

// ============================================================================
// Error Hierarchy
// ============================================================================

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("profile error: {0}")]
    Profile(String),

    #[error("secrets error: {0}")]
    Secrets(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("extension error: {0}")]
    Extension(String),

    #[error("policy locked: {key} is controlled by {policy_source}")]
    PolicyLocked { key: String, policy_source: String },

    #[error("capability denied: {capability} not declared in extension manifest")]
    CapabilityDenied { capability: String },

    #[error("profile isolation: access to {resource} denied by isolation contract")]
    IsolationDenied { resource: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Window and Geometry Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub id: WindowId,
    pub app_id: AppId,
    pub title: String,
    pub workspace_id: WorkspaceId,
    pub monitor_id: MonitorId,
    pub geometry: Geometry,
    pub is_focused: bool,
    pub is_minimized: bool,
    pub is_fullscreen: bool,
    pub profile_id: ProfileId,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Padding {
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
    pub left: u32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- AppId tests (v1 behavioral spec) --

    #[test]
    fn app_id_last_segment_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert_eq!(id.last_segment(), "ghostty");
    }

    #[test]
    fn app_id_last_segment_simple() {
        let id = AppId::new("firefox");
        assert_eq!(id.last_segment(), "firefox");
    }

    #[test]
    fn app_id_matches_full() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("com.mitchellh.ghostty"));
    }

    #[test]
    fn app_id_matches_last_segment() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_case_insensitive() {
        let id = AppId::new("com.mitchellh.Ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_other_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("org.example.ghostty"));
    }

    #[test]
    fn app_id_no_match() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(!id.matches("firefox"));
    }

    // -- SecretRef debug redaction --

    #[test]
    fn secret_ref_debug_does_not_leak_values() {
        let r = SecretRef::Keyring {
            secret: "work/token".into(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("keyring:work/token"));
        // The ref path is safe to log; the resolved VALUE never appears in this type.
    }

    // -- Sensitivity ordering --

    #[test]
    fn sensitivity_ordering() {
        assert!(SensitivityClass::Public < SensitivityClass::Confidential);
        assert!(SensitivityClass::Confidential < SensitivityClass::Secret);
        assert!(SensitivityClass::Secret < SensitivityClass::TopSecret);
    }

    // -- SecurityLevel ordering --

    #[test]
    fn security_level_ordering() {
        assert!(SecurityLevel::Open < SecurityLevel::Internal);
        assert!(SecurityLevel::Internal < SecurityLevel::ProfileScoped);
        assert!(SecurityLevel::ProfileScoped < SecurityLevel::SecretsOnly);
    }

    // -- Serialization round-trip property tests --

    proptest! {
        #[test]
        fn profile_id_roundtrip_postcard(n in any::<u128>()) {
            let id = ProfileId::from_uuid(Uuid::from_u128(n));
            let bytes = postcard::to_allocvec(&id).unwrap();
            let decoded: ProfileId = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn window_id_roundtrip_json(n in any::<u128>()) {
            let id = WindowId::from_uuid(Uuid::from_u128(n));
            let json = serde_json::to_string(&id).unwrap();
            let decoded: WindowId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn app_id_roundtrip_json(s in "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}") {
            let id = AppId::new(s);
            let json = serde_json::to_string(&id).unwrap();
            let decoded: AppId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn sensitivity_roundtrip_json(idx in 0u8..4) {
            let class = match idx {
                0 => SensitivityClass::Public,
                1 => SensitivityClass::Confidential,
                2 => SensitivityClass::Secret,
                _ => SensitivityClass::TopSecret,
            };
            let json = serde_json::to_string(&class).unwrap();
            let decoded: SensitivityClass = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(class, decoded);
        }

        #[test]
        fn geometry_roundtrip_postcard(x in any::<i32>(), y in any::<i32>(), w in any::<u32>(), h in any::<u32>()) {
            let geo = Geometry { x, y, width: w, height: h };
            let bytes = postcard::to_allocvec(&geo).unwrap();
            let decoded: Geometry = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(geo, decoded);
        }
    }

    // -- EventKind forward compatibility --

    #[test]
    fn event_kind_unknown_variant_deserializes() {
        // Externally-tagged: unknown variant name maps to Unknown via #[serde(other)]
        let json = r#""FutureEventV99""#;
        let event: EventKind = serde_json::from_str(json).unwrap();
        assert!(matches!(event, EventKind::Unknown));
    }

    #[test]
    fn event_kind_known_variant_roundtrips() {
        let event = EventKind::DaemonStarted {
            daemon_id: DaemonId::from_uuid(Uuid::from_u128(42)),
            version: "0.1.0".into(),
            capabilities: vec!["wm".into(), "tiling".into()],
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EventKind = serde_json::from_str(&json).unwrap();
        // Verify it round-trips to the same variant (not Unknown)
        assert!(matches!(decoded, EventKind::DaemonStarted { .. }));
    }
}
