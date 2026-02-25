//! Filesystem-based config hot-reload using the `notify` crate.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use crate::schema::Config;

/// Watches config file paths for changes and triggers reload + validation.
pub struct ConfigWatcher {
    _watcher: RecommendedWatcher,
    current: Arc<RwLock<Config>>,
}

impl ConfigWatcher {
    /// Create a new config watcher monitoring the given paths.
    ///
    /// Returns the watcher and a clone of the shared config state.
    /// The config is reloaded (with validation) whenever a watched file changes.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem watcher cannot be initialized.
    pub fn new(
        config_paths: Vec<PathBuf>,
        initial_config: Config,
    ) -> core_types::Result<(Self, Arc<RwLock<Config>>)> {
        let current = Arc::new(RwLock::new(initial_config));
        let current_clone = Arc::clone(&current);

        let watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        info!(?event, "config file changed, reloading");
                        match crate::loader::load_config(None) {
                            Ok(new_config) => {
                                let diags = crate::validation::validate(&new_config);
                                let has_errors = diags
                                    .iter()
                                    .any(|d| d.severity == crate::validation::DiagnosticSeverity::Error);
                                if has_errors {
                                    warn!("config reload rejected: validation errors");
                                    for d in &diags {
                                        warn!(message = %d.message, "config diagnostic");
                                    }
                                } else {
                                    if let Ok(mut guard) = current_clone.write() {
                                        *guard = new_config;
                                        info!("config reloaded successfully");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "config reload failed");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "filesystem watcher error");
                }
            }
        })
        .map_err(|e| core_types::Error::Config(format!("failed to create watcher: {e}")))?;

        let mut w = Self {
            _watcher: watcher,
            current: Arc::clone(&current),
        };

        for path in &config_paths {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    if let Err(e) = w._watcher.watch(parent, RecursiveMode::NonRecursive) {
                        warn!(path = %parent.display(), error = %e, "failed to watch config directory");
                    }
                }
            }
        }

        Ok((w, current))
    }

    /// Get a read handle to the current configuration.
    #[must_use]
    pub fn current(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.current)
    }
}
