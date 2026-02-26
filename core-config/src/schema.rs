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
    /// Default trust profile on startup.
    pub default_profile: core_types::TrustProfileName,

    /// IPC bus configuration.
    pub ipc: IpcConfig,

    /// Logging configuration.
    pub logging: LogConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            default_profile: core_types::TrustProfileName::try_from("default").expect("hardcoded valid name"),
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
    pub name: core_types::TrustProfileName,
    pub extends: Option<core_types::TrustProfileName>,
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
            name: core_types::TrustProfileName::try_from("default").expect("hardcoded valid name"),
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
    /// `WiFi` SSID triggers.
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

/// Window manager overlay configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WmConfig {
    /// Characters used for Vimium-style window hints (each char = one hint key).
    pub hint_keys: String,
    /// Delay (ms) before transitioning from border-only to full overlay.
    pub overlay_delay_ms: u32,
    /// Delay (ms) after activation before dismissing the overlay.
    pub activation_delay_ms: u32,
    /// Border width (px) for the focused window indicator.
    pub border_width: f32,
    /// Border color as hex (e.g., "#89b4fa").
    pub border_color: String,
    /// Number of recent windows for quick-switch (Alt-release during border-only).
    pub quick_switch_threshold: u32,
    /// Show window titles in the overlay.
    pub show_title: bool,
    /// Show app IDs in the overlay.
    pub show_app_id: bool,
    /// Maximum windows visible in the overlay list.
    pub max_visible_windows: u32,
}

impl Default for WmConfig {
    fn default() -> Self {
        Self {
            hint_keys: "asdfghjkl".into(),
            overlay_delay_ms: 150,
            activation_delay_ms: 200,
            border_width: 4.0,
            border_color: "#89b4fa".into(),
            quick_switch_threshold: 2,
            show_title: true,
            show_app_id: false,
            max_visible_windows: 20,
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
    /// Dotted key path (e.g. "`clipboard.max_history`").
    pub key: String,
    /// The enforced value.
    pub value: toml::Value,
    /// Source of the policy (e.g. "enterprise-mdm", "/etc/pds/policy.toml").
    pub source: String,
}
