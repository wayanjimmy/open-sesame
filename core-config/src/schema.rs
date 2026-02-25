//! Configuration schema types.

use core_types::SecretRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level PDS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema version for forward migration.
    pub config_version: u32,

    /// Global settings that apply across all profiles.
    pub global: GlobalConfig,

    /// Named profiles (key is profile name).
    pub profiles: BTreeMap<String, ProfileConfig>,

    /// System policy overrides (read-only at runtime).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<PolicyOverride>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 2,
            global: GlobalConfig::default(),
            profiles: BTreeMap::new(),
            policy: Vec::new(),
        }
    }
}

/// Global settings that apply across all profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    /// Default profile on startup.
    pub default_profile: String,

    /// IPC bus configuration.
    pub ipc: IpcConfig,

    /// Logging configuration.
    pub logging: LogConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            default_profile: "default".into(),
            ipc: IpcConfig::default(),
            logging: LogConfig::default(),
        }
    }
}

/// IPC bus configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpcConfig {
    /// Custom socket path override. `None` uses platform default.
    pub socket_path: Option<String>,

    /// Channel capacity per subscriber.
    pub channel_capacity: usize,

    /// Grace period (ms) before disconnecting slow subscribers.
    pub slow_subscriber_timeout_ms: u64,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            channel_capacity: 1024,
            slow_subscriber_timeout_ms: 5000,
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Default log level.
    pub level: String,

    /// Enable JSON-structured output.
    pub json: bool,

    /// Enable journald integration (Linux only).
    pub journald: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
            journald: true,
        }
    }
}

/// Per-profile configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileConfig {
    pub name: String,
    pub extends: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub activation: ActivationConfig,
    pub secrets: SecretsConfig,
    pub clipboard: ClipboardConfig,
    pub input: InputConfig,
    pub wm: WmConfig,
    pub launcher: LauncherConfig,
    pub audit: AuditConfig,

    /// Platform-specific overrides.
    #[serde(default)]
    pub platform: PlatformOverrides,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            extends: None,
            color: None,
            icon: None,
            activation: ActivationConfig::default(),
            secrets: SecretsConfig::default(),
            clipboard: ClipboardConfig::default(),
            input: InputConfig::default(),
            wm: WmConfig::default(),
            launcher: LauncherConfig::default(),
            audit: AuditConfig::default(),
            platform: PlatformOverrides::default(),
        }
    }
}

/// Profile activation rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivationConfig {
    /// WiFi SSID triggers.
    pub wifi_ssids: Vec<String>,
    /// USB device triggers (vendor:product pairs).
    pub usb_devices: Vec<String>,
    /// Time-of-day rules (cron-like expressions).
    pub time_rules: Vec<String>,
    /// Hardware security key presence.
    pub require_security_key: bool,
}

/// Secrets configuration for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    /// Default secret provider for this profile.
    pub provider: Option<String>,
    /// Pre-resolved secrets for this profile.
    pub secrets: BTreeMap<String, SecretRef>,
}

/// Clipboard configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Maximum history entries.
    pub max_history: usize,
    /// TTL for sensitive entries (seconds).
    pub sensitive_ttl_s: u64,
    /// Enable sensitivity detection.
    pub detect_sensitive: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            max_history: 1000,
            sensitive_ttl_s: 30,
            detect_sensitive: true,
        }
    }
}

/// Input remapping configuration for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InputConfig {
    /// Key binding layers.
    pub layers: BTreeMap<String, BTreeMap<String, String>>,
}

/// Window manager configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WmConfig {
    /// Gap size between tiled windows (pixels).
    pub gap_size: u32,
    /// Default layout name.
    pub default_layout: String,
}

impl Default for WmConfig {
    fn default() -> Self {
        Self {
            gap_size: 8,
            default_layout: "tiling".into(),
        }
    }
}

/// Launcher configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LauncherConfig {
    /// Maximum results to display.
    pub max_results: usize,
    /// Enable frecency-based ranking.
    pub frecency: bool,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            max_results: 20,
            frecency: true,
        }
    }
}

/// Audit log configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging for this profile.
    pub enabled: bool,
    /// Retention period (days).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
        }
    }
}

/// Platform-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<toml::Value>,
}

/// A system policy override that locks a configuration key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOverride {
    /// Dotted key path (e.g. "clipboard.max_history").
    pub key: String,
    /// The enforced value.
    pub value: toml::Value,
    /// Source of the policy (e.g. "enterprise-mdm", "/etc/pds/policy.toml").
    pub source: String,
}
