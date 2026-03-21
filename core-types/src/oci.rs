use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{Error, Result};

/// OCI-style content-addressable reference for extensions and policies.
///
/// Format: `registry/principal/scope:revision[@provenance]`
///
/// Examples:
/// - `registry.example.com/org/extension:1.0.0`
/// - `registry.example.com/org/extension:1.0.0@sha256:abc123`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OciReference {
    pub registry: String,
    pub principal: String,
    pub scope: String,
    pub revision: String,
    pub provenance: Option<String>,
}

impl OciReference {
    /// Parse an OCI reference string.
    ///
    /// Expected format: `registry/principal/scope:revision[@provenance]`
    ///
    /// # Errors
    ///
    /// Returns `Error::Validation` if the input is empty or malformed.
    pub fn parse(input: &str) -> Result<Self> {
        input.parse()
    }
}

impl std::str::FromStr for OciReference {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::Validation("OCI reference must not be empty".into()));
        }

        // Split off provenance (@...)
        let (main, provenance) = match s.rsplit_once('@') {
            Some((m, p)) if !p.is_empty() => (m, Some(p.to_owned())),
            Some((_, _)) => {
                return Err(Error::Validation(
                    "OCI reference has empty provenance after '@'".into(),
                ));
            }
            None => (s, None),
        };

        // Split off revision (:...)
        let (path, revision) = match main.rsplit_once(':') {
            Some((p, r)) if !r.is_empty() => (p, r.to_owned()),
            Some((_, _)) => {
                return Err(Error::Validation(
                    "OCI reference has empty revision after ':'".into(),
                ));
            }
            None => {
                return Err(Error::Validation(
                    "OCI reference missing ':revision'".into(),
                ));
            }
        };

        // Split path into registry/principal/scope (at least 3 segments)
        let segments: Vec<&str> = path.splitn(3, '/').collect();
        if segments.len() < 3 {
            return Err(Error::Validation(format!(
                "OCI reference path must have at least 3 segments (registry/principal/scope), got {}",
                segments.len()
            )));
        }

        for (name, val) in [
            ("registry", segments[0]),
            ("principal", segments[1]),
            ("scope", segments[2]),
        ] {
            if val.is_empty() {
                return Err(Error::Validation(format!(
                    "OCI reference {name} must not be empty"
                )));
            }
        }

        Ok(Self {
            registry: segments[0].to_owned(),
            principal: segments[1].to_owned(),
            scope: segments[2].to_owned(),
            revision,
            provenance,
        })
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}:{}",
            self.registry, self.principal, self.scope, self.revision
        )?;
        if let Some(ref prov) = self.provenance {
            write!(f, "@{prov}")?;
        }
        Ok(())
    }
}
