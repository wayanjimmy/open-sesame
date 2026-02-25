//! Transport abstractions and socket path resolution.

use std::path::PathBuf;

/// Peer credentials obtained from the transport layer.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Process ID of the peer.
    pub pid: u32,
    /// User ID of the peer (Unix). On Windows, this is 0 (use SID instead).
    pub uid: u32,
}

/// Resolve the platform-appropriate IPC socket path.
///
/// # Errors
///
/// Returns an error if required platform directories cannot be determined
/// (e.g. `XDG_RUNTIME_DIR` unset on Linux, no home directory on macOS).
pub fn socket_path() -> core_types::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let runtime = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
            core_types::Error::Platform(
                "XDG_RUNTIME_DIR is not set; cannot determine IPC socket path".into(),
            )
        })?;
        Ok(PathBuf::from(runtime).join("pds/bus.sock"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or_else(|| {
            core_types::Error::Platform("cannot determine home directory".into())
        })?;
        Ok(home.join("Library/Application Support/pds/bus.sock"))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(PathBuf::from(r"\\.\pipe\pds\bus"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(core_types::Error::Platform(
            "unsupported platform: cannot determine IPC socket path".into(),
        ))
    }
}
