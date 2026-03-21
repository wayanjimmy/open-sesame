use serde::{Deserialize, Serialize};

use crate::ids::{ClipboardEntryId, ProfileId};
use crate::profile::TrustProfileName;
use crate::security::SensitivityClass;

/// Summary of a profile for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub name: TrustProfileName,
    /// Whether this profile's vault is currently open and serving secrets.
    pub is_active: bool,
    /// Whether this profile is the default for new unscoped launches.
    pub is_default: bool,
}

/// A single launcher result entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    pub entry_id: String,
    pub name: String,
    pub icon: Option<String>,
    pub score: f64,
}

/// A clipboard history entry summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub entry_id: ClipboardEntryId,
    pub content_type: String,
    pub sensitivity: SensitivityClass,
    pub profile_id: ProfileId,
    /// Truncated preview (first 80 chars).
    pub preview: String,
    pub timestamp_ms: u64,
}

/// Input layer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputLayerInfo {
    pub name: String,
    pub is_active: bool,
    pub remap_count: u32,
}

/// Snippet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetInfo {
    pub trigger: String,
    pub template_preview: String,
}
