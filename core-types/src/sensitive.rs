use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Sensitive byte buffer with automatic zeroize-on-drop.
///
/// Used for secret values and passwords in IPC `EventKind` variants.
/// Zeroes the backing memory when dropped to prevent heap forensics.
/// Debug output is redacted to prevent log exposure.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0.len())
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
