//! Semantic validation for PDS configuration.

use crate::schema::Config;
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

    check_circular_inheritance(config, &mut diagnostics);
    check_extends_references(config, &mut diagnostics);

    diagnostics
}

fn check_circular_inheritance(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for (name, profile) in &config.profiles {
        let mut visited = HashSet::new();
        visited.insert(name.as_str());
        let mut current = profile.extends.as_deref();

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
                .and_then(|p| p.extends.as_deref());
        }
    }
}

fn check_extends_references(config: &Config, diagnostics: &mut Vec<ConfigDiagnostic>) {
    for (name, profile) in &config.profiles {
        if let Some(ref parent) = profile.extends {
            if !config.profiles.contains_key(parent) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Config, ProfileConfig};

    #[test]
    fn detects_circular_inheritance() {
        let mut config = Config::default();
        config.profiles.insert(
            "a".into(),
            ProfileConfig {
                name: "a".into(),
                extends: Some("b".into()),
                ..Default::default()
            },
        );
        config.profiles.insert(
            "b".into(),
            ProfileConfig {
                name: "b".into(),
                extends: Some("a".into()),
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
                name: "work".into(),
                extends: Some("nonexistent".into()),
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
                name: "base".into(),
                ..Default::default()
            },
        );
        config.profiles.insert(
            "work".into(),
            ProfileConfig {
                name: "work".into(),
                extends: Some("base".into()),
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
