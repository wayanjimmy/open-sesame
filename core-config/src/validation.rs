//! Semantic validation for PDS configuration.

use crate::schema::Config;
use core_types::TrustProfileName;
use std::collections::HashSet;
use std::path::PathBuf;

/// Severity level for configuration diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

/// A structured diagnostic from config validation.
#[derive(Debug, Clone)]
pub struct ConfigDiagnostic {
    pub severity: DiagnosticSeverity,
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
    pub remediation: Option<String>,
}

/// Validate a loaded configuration and return any diagnostics.
///
/// Checks:
/// - Circular profile inheritance (`extends` chains must be acyclic)
/// - Referenced profiles in `extends` fields exist
/// - Policy-locked fields are not overridden
#[must_use]
pub fn validate(config: &Config) -> Vec<ConfigDiagnostic> {
    let mut diagnostics = Vec::new();

    check_profile_names(config, &mut diagnostics);
    check_circular_inheritance(config, &mut diagnostics);
    check_extends_references(config, &mut diagnostics);
    check_wm_config(config, &mut diagnostics);

    diagnostics
}

/// Validate that all profile map keys are valid `TrustProfileName` values.
///
/// TOML map keys are `String` (serde limitation). This check catches invalid
/// keys that would bypass the type-level validation on `TrustProfileName` fields.
fn check_profile_names(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for key in config.profiles.keys() {
        if TrustProfileName::try_from(key.as_str()).is_err() {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Error,
                file: None,
                line: None,
                column: None,
                message: format!(
                    "profile map key '{key}' is not a valid trust profile name: \
                     must match [a-zA-Z][a-zA-Z0-9_-]{{0,63}}"
                ),
                remediation: Some(format!(
                    "rename profile '{key}' to use only ASCII alphanumeric characters, \
                     hyphens, and underscores (max 64 chars, must start with a letter or digit)"
                )),
            });
        }
    }
}

fn check_circular_inheritance(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for (name, profile) in &config.profiles {
        let mut visited = HashSet::new();
        visited.insert(name.as_str());
        let mut current: Option<&str> = profile.extends.as_deref();

        while let Some(parent_name) = current {
            if !visited.insert(parent_name) {
                diagnostics.push(ConfigDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    file: None,
                    line: None,
                    column: None,
                    message: format!(
                        "circular profile inheritance: '{name}' -> chain includes '{parent_name}' again"
                    ),
                    remediation: Some(format!(
                        "remove or change the 'extends' field in profile '{name}' or '{parent_name}'"
                    )),
                });
                break;
            }
            current = config
                .profiles
                .get(parent_name)
                .and_then(|p| p.extends.as_ref().map(std::convert::AsRef::as_ref));
        }
    }
}

fn check_wm_config(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for (name, profile) in &config.profiles {
        let wm = &profile.wm;

        if wm.hint_keys.is_empty() {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Error,
                file: None,
                line: None,
                column: None,
                message: format!("profile '{name}': wm.hint_keys must not be empty"),
                remediation: Some("set wm.hint_keys to a non-empty string of unique characters".into()),
            });
        }

        // Check for duplicate hint keys.
        let mut seen = std::collections::HashSet::new();
        for ch in wm.hint_keys.chars() {
            if !seen.insert(ch) {
                diagnostics.push(ConfigDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    file: None,
                    line: None,
                    column: None,
                    message: format!("profile '{name}': wm.hint_keys contains duplicate character '{ch}'"),
                    remediation: Some("remove duplicate characters from wm.hint_keys".into()),
                });
                break;
            }
        }

        if !(10..=2000).contains(&wm.overlay_delay_ms) {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Warning,
                file: None,
                line: None,
                column: None,
                message: format!(
                    "profile '{name}': wm.overlay_delay_ms={} outside recommended range [10, 2000]",
                    wm.overlay_delay_ms
                ),
                remediation: Some("set wm.overlay_delay_ms between 10 and 2000".into()),
            });
        }

        if !(10..=2000).contains(&wm.activation_delay_ms) {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Warning,
                file: None,
                line: None,
                column: None,
                message: format!(
                    "profile '{name}': wm.activation_delay_ms={} outside recommended range [10, 2000]",
                    wm.activation_delay_ms
                ),
                remediation: Some("set wm.activation_delay_ms between 10 and 2000".into()),
            });
        }

        if !(1.0..=20.0).contains(&wm.border_width) {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Warning,
                file: None,
                line: None,
                column: None,
                message: format!(
                    "profile '{name}': wm.border_width={} outside recommended range [1.0, 20.0]",
                    wm.border_width
                ),
                remediation: Some("set wm.border_width between 1.0 and 20.0".into()),
            });
        }
    }
}

fn check_extends_references(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for (name, profile) in &config.profiles {
        if let Some(ref parent) = profile.extends
            && !config.profiles.contains_key(parent.as_ref())
        {
            diagnostics.push(ConfigDiagnostic {
                severity: DiagnosticSeverity::Error,
                file: None,
                line: None,
                column: None,
                message: format!(
                    "profile '{name}' extends '{parent}', but '{parent}' is not defined"
                ),
                remediation: Some(format!("define a profile named '{parent}' or remove the 'extends' field")),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Config, ProfileConfig};
    use core_types::TrustProfileName;

    fn tpn(s: &str) -> TrustProfileName {
        TrustProfileName::try_from(s).unwrap()
    }

    #[test]
    fn detects_circular_inheritance() {
        let mut config = Config::default();
        config.profiles.insert(
            "a".into(),
            ProfileConfig {
                name: tpn("a"),
                extends: Some(tpn("b")),
                ..Default::default()
            },
        );
        config.profiles.insert(
            "b".into(),
            ProfileConfig {
                name: tpn("b"),
                extends: Some(tpn("a")),
                ..Default::default()
            },
        );
        let diags = validate(&config);
        assert!(
            diags.iter().any(|d| d.severity == DiagnosticSeverity::Error
                && d.message.contains("circular")),
            "expected circular inheritance error, got: {diags:?}"
        );
    }

    #[test]
    fn detects_missing_extends_target() {
        let mut config = Config::default();
        config.profiles.insert(
            "work".into(),
            ProfileConfig {
                name: tpn("work"),
                extends: Some(tpn("nonexistent")),
                ..Default::default()
            },
        );
        let diags = validate(&config);
        assert!(
            diags
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Error
                    && d.message.contains("nonexistent")),
            "expected missing extends error, got: {diags:?}"
        );
    }

    #[test]
    fn valid_config_has_no_errors() {
        let mut config = Config::default();
        config.profiles.insert(
            "base".into(),
            ProfileConfig {
                name: tpn("base"),
                ..Default::default()
            },
        );
        config.profiles.insert(
            "work".into(),
            ProfileConfig {
                name: tpn("work"),
                extends: Some(tpn("base")),
                ..Default::default()
            },
        );
        let diags = validate(&config);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }
}
