use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Shared constants — single source of truth for cross-crate values
// ============================================================================

/// Level-0 namespace seed for deterministic profile-ID derivation.
///
/// Used as the root UUID v5 namespace from which installation namespaces,
/// org namespaces, and ultimately `ProfileId` values are derived.
/// **Never use directly for `ProfileId` derivation** — derive an `install_ns` first.
pub const PROFILE_NAMESPACE: Uuid = Uuid::from_bytes([
    0x4c, 0x45, 0xa6, 0x4f, 0xab, 0xcd, 0x59, 0x77, 0xbc, 0x73, 0x99, 0xd4, 0xc9, 0x3d, 0x66, 0x8b,
]);

/// Canonical name for the default profile created during `sesame init`.
///
/// All crates that need to reference the default profile should use this constant
/// rather than hardcoding `"default"` to prevent silent divergence.
pub const DEFAULT_PROFILE_NAME: &str = "default";

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
            #[allow(clippy::cast_possible_truncation)] // Uptime > 584 years before truncation
            monotonic_ns: mono.as_nanos() as u64,
            #[allow(clippy::cast_possible_truncation)] // Wall clock > 584M years before truncation
            wall_ms: wall.as_millis() as u64,
        }
    }
}
