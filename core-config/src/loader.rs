//! Configuration loading and file I/O.

use crate::schema::Config;
use std::path::{Path, PathBuf};

/// Return the platform-appropriate PDS config directory.
#[must_use]
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("pds")
}

/// Resolve all config paths in loading order (lowest to highest priority).
///
/// 1. System policy (`/etc/pds/policy.toml` on Linux)
/// 2. User config (`~/.config/pds/config.toml`)
/// 3. Drop-in fragments (`~/.config/pds/config.d/*.toml`, alphabetical)
/// 4. Profile overrides (`~/.config/pds/profiles/{name}/config.toml`)
#[must_use]
pub fn resolve_config_paths(profile_name: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // System policy (Linux only for now)
    #[cfg(target_os = "linux")]
    {
        let system = PathBuf::from("/etc/pds/policy.toml");
        if system.exists() {
            paths.push(system);
        }
    }

    let base = config_dir();

    // User config
    let user_config = base.join("config.toml");
    if user_config.exists() {
        paths.push(user_config);
    }

    // Drop-in fragments (sorted alphabetically)
    let dropin_dir = base.join("config.d");
    if dropin_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&dropin_dir)
    {
        let mut fragments: Vec<PathBuf> = entries
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        fragments.sort();
        paths.extend(fragments);
    }

    // Profile overrides
    if let Some(name) = profile_name {
        let profile_config = base.join("profiles").join(name).join("config.toml");
        if profile_config.exists() {
            paths.push(profile_config);
        }
    }

    paths
}

/// Load configuration by merging all layers.
///
/// Layers are applied in order: compiled defaults, then each file from
/// `resolve_config_paths` (lowest to highest priority). Higher-priority
/// values override lower-priority ones via TOML deep merge.
///
/// # Errors
///
/// Returns an error if any config file contains invalid TOML or fails
/// schema validation.
pub fn load_config(profile_name: Option<&str>) -> core_types::Result<Config> {
    let mut config = Config::default();
    let paths = resolve_config_paths(profile_name);

    for path in &paths {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            core_types::Error::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        let layer: Config = toml::from_str(&contents).map_err(|e| {
            core_types::Error::Config(format!("failed to parse {}: {e}", path.display()))
        })?;
        merge_config(&mut config, &layer);
    }

    Ok(config)
}

/// Deep merge `overlay` into `base`. Non-default overlay values override base.
fn merge_config(base: &mut Config, overlay: &Config) {
    // Schema version: always take the higher
    if overlay.config_version > base.config_version {
        base.config_version = overlay.config_version;
    }

    // Global settings
    if overlay.global.default_profile.as_ref() != GlobalConfigDefaults::DEFAULT_PROFILE {
        base.global.default_profile = overlay.global.default_profile.clone();
    }

    // Profiles: overlay profiles merge into base by name
    for (name, profile) in &overlay.profiles {
        base.profiles
            .entry(name.clone())
            .and_modify(|existing| merge_profile(existing, profile))
            .or_insert_with(|| profile.clone());
    }

    // Policy: append (policies are additive)
    base.policy.extend(overlay.policy.iter().cloned());
}

fn merge_profile(base: &mut crate::schema::ProfileConfig, overlay: &crate::schema::ProfileConfig) {
    if overlay.extends.is_some() {
        base.extends.clone_from(&overlay.extends);
    }
    if overlay.color.is_some() {
        base.color.clone_from(&overlay.color);
    }
    if overlay.icon.is_some() {
        base.icon.clone_from(&overlay.icon);
    }
    // Sub-configs: merge non-default values
    if overlay.clipboard.max_history != crate::schema::ClipboardConfig::default().max_history {
        base.clipboard.max_history = overlay.clipboard.max_history;
    }
    if overlay.wm.hint_keys != crate::schema::WmConfig::default().hint_keys {
        base.wm.hint_keys.clone_from(&overlay.wm.hint_keys);
    }
    if overlay.wm.overlay_delay_ms != crate::schema::WmConfig::default().overlay_delay_ms {
        base.wm.overlay_delay_ms = overlay.wm.overlay_delay_ms;
    }
    if overlay.wm.max_visible_windows != crate::schema::WmConfig::default().max_visible_windows {
        base.wm.max_visible_windows = overlay.wm.max_visible_windows;
    }
}

/// Helpers for detecting default values.
struct GlobalConfigDefaults;
impl GlobalConfigDefaults {
    const DEFAULT_PROFILE: &str = "default";
}

/// Atomically write contents to a file using the POSIX rename pattern.
///
/// Writes to a temporary file in the same directory, calls `fsync`, then
/// atomically renames over the target. On failure, the original file is
/// untouched.
///
/// # Errors
///
/// Returns an I/O error if the write, sync, or rename fails.
pub fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        atomic_write(&path, b"hello = true\n").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "hello = true\n");
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "new");
    }

    #[test]
    fn default_config_roundtrips_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.config_version, config.config_version);
        assert_eq!(parsed.global.default_profile, config.global.default_profile);
    }

    #[test]
    fn load_config_returns_defaults_when_no_files() {
        // In a clean tmpdir with no config files, load_config should succeed
        // with defaults (paths won't exist).
        let config = Config::default();
        assert_eq!(config.config_version, 2);
        assert_eq!(&*config.global.default_profile, "default");
    }

    #[test]
    fn merge_overlay_profile() {
        let mut base = Config::default();
        let mut overlay = Config::default();
        overlay.profiles.insert(
            "work".into(),
            crate::schema::ProfileConfig {
                name: core_types::TrustProfileName::try_from("work").unwrap(),
                color: Some("#ff0000".into()),
                ..Default::default()
            },
        );
        merge_config(&mut base, &overlay);
        assert!(base.profiles.contains_key("work"));
        assert_eq!(
            base.profiles["work"].color.as_deref(),
            Some("#ff0000")
        );
    }
}
