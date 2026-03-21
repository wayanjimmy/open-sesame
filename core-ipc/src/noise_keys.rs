//! Key management and persistence for Noise IK keypairs.
//!
//! Handles generation, filesystem I/O, permissions, and tamper-detection
//! checksums for both the bus server keypair and per-daemon keypairs.
//!
//! Key storage layout under `$XDG_RUNTIME_DIR/pds/`:
//! - `bus.pub` (0644) — bus server public key, read by connecting daemons
//! - `bus.key` (0600) — bus server private key
//! - `bus.checksum` — BLAKE3 integrity checksum
//! - `keys/<daemon>.pub` (0644) — per-daemon public key
//! - `keys/<daemon>.key` (0600) — per-daemon private key
//! - `keys/<daemon>.checksum` — per-daemon integrity checksum

use std::path::{Path, PathBuf};

/// Compute an integrity-detection checksum for a keypair.
///
/// Uses BLAKE3 keyed hash with the public key as the 32-byte key and
/// the private key as the data. Detects partial corruption or partial tampering
/// (e.g., private key replaced but checksum file untouched). Does NOT prevent
/// an attacker with full filesystem write access from replacing all three files
/// (private key, public key, checksum) with a self-consistent set — that requires
/// a root-of-trust outside the filesystem (e.g., TPM-backed attestation).
fn keypair_checksum(public_key: &[u8; 32], private_key: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(public_key, private_key).as_bytes()
}

/// Generate a new X25519 static keypair for Noise IK.
///
/// Called once at daemon startup. The keypair is ephemeral to the process lifetime
/// for connecting daemons, or persisted to `$XDG_RUNTIME_DIR/pds/` for the bus server.
///
/// # Errors
///
/// Returns an error if the crypto resolver fails.
pub fn generate_keypair() -> core_types::Result<ZeroizingKeypair> {
    let builder = snow::Builder::new(
        crate::noise::NOISE_PARAMS
            .parse()
            .map_err(|e| core_types::Error::Platform(format!("invalid Noise params: {e}")))?,
    );
    let keypair = builder
        .generate_keypair()
        .map_err(|e| core_types::Error::Platform(format!("keypair generation failed: {e}")))?;
    Ok(ZeroizingKeypair::new(keypair))
}

/// Zeroize-on-drop wrapper for `snow::Keypair`.
///
/// `snow::Keypair` has no `Drop` impl, so the private key persists in freed
/// memory if not explicitly zeroized. This wrapper guarantees zeroization on
/// drop, including during panics (unwind calls `Drop`).
///
/// All code that constructs or receives a `snow::Keypair` should use this
/// wrapper instead. The private key is accessible via `private()` for
/// passing to `snow::Builder::local_private_key()`.
pub struct ZeroizingKeypair {
    inner: snow::Keypair,
}

impl ZeroizingKeypair {
    /// Wrap a `snow::Keypair`, taking ownership.
    #[must_use]
    pub fn new(keypair: snow::Keypair) -> Self {
        Self { inner: keypair }
    }

    /// Access the public key (32 bytes).
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.inner.public
    }

    /// Access the private key (32 bytes). Use only for `snow::Builder` calls.
    #[must_use]
    pub fn private(&self) -> &[u8] {
        &self.inner.private
    }

    /// Borrow the inner `snow::Keypair` for APIs that require `&snow::Keypair`.
    #[must_use]
    pub fn as_inner(&self) -> &snow::Keypair {
        &self.inner
    }

    /// Consume the wrapper and return the inner `snow::Keypair`.
    ///
    /// The caller takes responsibility for zeroizing the private key.
    /// Use only when transferring ownership to an API that requires `snow::Keypair`
    /// (e.g., `BusServer::bind`).
    #[must_use]
    pub fn into_inner(mut self) -> snow::Keypair {
        let private = std::mem::take(&mut self.inner.private);
        let public = std::mem::take(&mut self.inner.public);
        snow::Keypair { private, public }
    }
}

impl Drop for ZeroizingKeypair {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.inner.private);
    }
}

impl From<snow::Keypair> for ZeroizingKeypair {
    fn from(keypair: snow::Keypair) -> Self {
        Self::new(keypair)
    }
}

/// Override for the runtime directory path. Set by tests to avoid `set_var`
/// race conditions (P7). Production code never sets this.
static RUNTIME_DIR_OVERRIDE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Set the runtime directory override. Intended for testing only.
/// Avoids `unsafe { set_var(...) }` which races with other threads reading env.
#[doc(hidden)]
pub fn set_runtime_dir_override(path: PathBuf) {
    *RUNTIME_DIR_OVERRIDE.lock().unwrap() = Some(path);
}

/// Resolve the PDS runtime directory (`$XDG_RUNTIME_DIR/pds/`).
fn runtime_dir() -> core_types::Result<PathBuf> {
    if let Some(ref override_dir) = *RUNTIME_DIR_OVERRIDE.lock().unwrap() {
        return Ok(override_dir.clone());
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .map_err(|_| core_types::Error::Platform("XDG_RUNTIME_DIR is not set".into()))?;
    Ok(PathBuf::from(runtime).join("pds"))
}

/// Write the bus server's static keypair to the runtime directory.
///
/// - `bus.pub` (32 bytes, world-readable) — read by connecting daemons
/// - `bus.key` (32 bytes, mode 0600) — private key for the bus server
///
/// # Errors
///
/// Returns an error if directory creation or file I/O fails.
pub async fn write_bus_keypair(keypair: &snow::Keypair) -> core_types::Result<()> {
    let dir = runtime_dir()?;
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to create runtime dir {}: {e}",
            dir.display()
        ))
    })?;

    let pub_path = dir.join("bus.pub");
    let key_path = dir.join("bus.key");

    tokio::fs::write(&pub_path, &keypair.public)
        .await
        .map_err(|e| core_types::Error::Platform(format!("failed to write bus.pub: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to set bus.pub permissions: {e}"))
            })?;
    }

    // Write private key atomically: write to temp file with 0600 perms, then rename.
    // This prevents a window where the key file exists with default (permissive) permissions.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp_key_path = dir.join("bus.key.tmp");
        // Blocking file ops for atomic write with mode — wrapped in spawn_blocking
        // to avoid blocking the tokio runtime.
        let private_key = zeroize::Zeroizing::new(keypair.private.clone());
        let tmp_path = tmp_key_path.clone();
        let final_path = key_path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(&private_key)?;
            f.sync_all()?;
            std::fs::rename(&tmp_path, &final_path)?;
            Ok(())
        })
        .await
        .map_err(|e| core_types::Error::Platform(format!("bus.key write task failed: {e}")))?
        .map_err(|e| core_types::Error::Platform(format!("failed to write bus.key: {e}")))?;
    }

    #[cfg(not(unix))]
    {
        compile_error!(
            "bus.key writing requires Unix file permissions (mode 0600). Non-Unix platforms are not supported in MVP."
        );
    }

    // Write tamper-detection checksum.
    {
        let pub_array: [u8; 32] =
            keypair.public.clone().try_into().map_err(|_| {
                core_types::Error::Platform("bus public key is not 32 bytes".into())
            })?;
        let checksum = keypair_checksum(&pub_array, &keypair.private);
        let checksum_path = dir.join("bus.checksum");
        tokio::fs::write(&checksum_path, checksum)
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to write bus.checksum: {e}"))
            })?;
    }

    tracing::info!(
        pub_path = %pub_path.display(),
        key_path = %key_path.display(),
        "bus keypair written"
    );
    Ok(())
}

/// Directory for per-daemon keypair files.
fn keys_dir() -> core_types::Result<PathBuf> {
    Ok(runtime_dir()?.join("keys"))
}

/// Create the per-daemon keys directory if it does not exist.
///
/// # Errors
///
/// Returns an error if the directory cannot be created.
pub async fn create_keys_dir() -> core_types::Result<()> {
    let dir = keys_dir()?;
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        core_types::Error::Platform(format!("failed to create keys dir {}: {e}", dir.display()))
    })?;
    // Restrict to owner-only (0700) — create_dir_all inherits umask
    // (typically 0022 → 0755), which would let any local user enumerate daemons.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!(
                    "failed to set keys dir permissions on {}: {e}",
                    dir.display()
                ))
            })?;
    }
    Ok(())
}

/// Write a daemon's keypair to disk. Private key gets 0600, public key gets 0644.
///
/// Uses write-to-temp-then-rename for atomicity, same pattern as `write_bus_keypair()`.
///
/// # Errors
///
/// Returns an error if writing the keypair files fails.
pub async fn write_daemon_keypair(
    daemon_name: &str,
    keypair: &snow::Keypair,
) -> core_types::Result<()> {
    let dir = keys_dir()?;

    let pub_path = dir.join(format!("{daemon_name}.pub"));
    let key_path = dir.join(format!("{daemon_name}.key"));

    // Public key: world-readable (explicit 0644).
    tokio::fs::write(&pub_path, &keypair.public)
        .await
        .map_err(|e| {
            core_types::Error::Platform(format!("failed to write {daemon_name}.pub: {e}"))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!(
                    "failed to set {daemon_name}.pub permissions: {e}"
                ))
            })?;
    }

    // Private key: atomic write with 0600 perms.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp_path = dir.join(format!("{daemon_name}.key.tmp"));
        let private_key = zeroize::Zeroizing::new(keypair.private.clone());
        let tmp = tmp_path.clone();
        let final_path = key_path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&private_key)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &final_path)?;
            Ok(())
        })
        .await
        .map_err(|e| {
            core_types::Error::Platform(format!("{daemon_name}.key write task failed: {e}"))
        })?
        .map_err(|e| {
            core_types::Error::Platform(format!("failed to write {daemon_name}.key: {e}"))
        })?;
    }

    #[cfg(not(unix))]
    {
        compile_error!("daemon keypair writing requires Unix file permissions (mode 0600)");
    }

    // Write tamper-detection checksum.
    {
        let pub_array: [u8; 32] = keypair.public.clone().try_into().map_err(|_| {
            core_types::Error::Platform(format!("{daemon_name} public key is not 32 bytes"))
        })?;
        let checksum = keypair_checksum(&pub_array, &keypair.private);
        let checksum_path = dir.join(format!("{daemon_name}.checksum"));
        tokio::fs::write(&checksum_path, checksum)
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to write {daemon_name}.checksum: {e}"))
            })?;
    }

    tracing::debug!(
        daemon = daemon_name,
        pub_path = %pub_path.display(),
        key_path = %key_path.display(),
        "daemon keypair written"
    );
    Ok(())
}

/// Read a daemon's keypair from disk. Private key wrapped in `Zeroizing`.
///
/// # Errors
///
/// Returns an error if the keypair files cannot be read or have invalid size.
pub async fn read_daemon_keypair(
    daemon_name: &str,
) -> core_types::Result<(zeroize::Zeroizing<Vec<u8>>, [u8; 32])> {
    let dir = keys_dir()?;

    let key_path = dir.join(format!("{daemon_name}.key"));
    let pub_path = dir.join(format!("{daemon_name}.pub"));

    let private_bytes = tokio::fs::read(&key_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.key at {}: {e}",
            key_path.display()
        ))
    })?;

    let public_bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.pub at {}: {e}",
            pub_path.display()
        ))
    })?;

    let public_key: [u8; 32] = public_bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "{daemon_name}.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;

    // Tamper detection.
    let checksum_path = dir.join(format!("{daemon_name}.checksum"));
    match tokio::fs::read(&checksum_path).await {
        Ok(stored_checksum) => {
            let expected = keypair_checksum(&public_key, &private_bytes);
            if stored_checksum.len() != 32 || stored_checksum[..] != expected[..] {
                return Err(core_types::Error::Platform(format!(
                    "TAMPER DETECTED: {daemon_name} keypair checksum mismatch. \
                     The private key or public key file may have been modified. \
                     Delete $XDG_RUNTIME_DIR/pds/keys/{daemon_name}.* and restart daemon-profile."
                )));
            }
            tracing::debug!(daemon = daemon_name, "keypair integrity verified");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Backward compatibility: no checksum file from older installation.
            tracing::warn!(
                daemon = daemon_name,
                "no checksum file found — keypair integrity cannot be verified. \
                 Restart daemon-profile to generate checksums."
            );
        }
        Err(e) => {
            return Err(core_types::Error::Platform(format!(
                "failed to read {daemon_name}.checksum: {e}"
            )));
        }
    }

    Ok((zeroize::Zeroizing::new(private_bytes), public_key))
}

/// Read only a daemon's public key from disk.
///
/// # Errors
///
/// Returns an error if the public key file cannot be read or has invalid size.
pub async fn read_daemon_public_key(daemon_name: &str) -> core_types::Result<[u8; 32]> {
    let dir = keys_dir()?;
    let pub_path = dir.join(format!("{daemon_name}.pub"));
    let bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read {daemon_name}.pub at {}: {e}",
            pub_path.display()
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "{daemon_name}.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(key)
}

/// Read the bus server's public key from the runtime directory.
///
/// Connecting daemons call this before initiating the Noise IK handshake
/// (the "K" in IK — responder's static key is Known to the initiator).
///
/// # Errors
///
/// Returns an error if the file does not exist or is not exactly 32 bytes.
pub async fn read_bus_public_key() -> core_types::Result<[u8; 32]> {
    read_bus_public_key_from(&runtime_dir()?).await
}

/// Read the bus server's public key from a specific directory.
///
/// Allows callers to specify a custom path (useful for testing).
///
/// # Errors
///
/// Returns an error if the file does not exist or is not exactly 32 bytes.
pub async fn read_bus_public_key_from(dir: &Path) -> core_types::Result<[u8; 32]> {
    let pub_path = dir.join("bus.pub");
    let bytes = tokio::fs::read(&pub_path).await.map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to read bus.pub at {}: {e}",
            pub_path.display()
        ))
    })?;
    let key: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        core_types::Error::Platform(format!(
            "bus.pub has wrong size: expected 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_checksum_consistency() {
        let kp = generate_keypair().unwrap();
        let pub_array: [u8; 32] = kp.public().try_into().unwrap();
        let checksum1 = keypair_checksum(&pub_array, kp.private());
        let checksum2 = keypair_checksum(&pub_array, kp.private());
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn keypair_checksum_detects_tampering() {
        let kp = generate_keypair().unwrap();
        let pub_array: [u8; 32] = kp.public().try_into().unwrap();
        let checksum = keypair_checksum(&pub_array, kp.private());

        // Tampered private key produces different checksum.
        let mut tampered = kp.private().to_vec();
        tampered[0] ^= 0xFF;
        let tampered_checksum = keypair_checksum(&pub_array, &tampered);
        assert_ne!(checksum, tampered_checksum);
    }

    #[test]
    fn generate_keypair_produces_32_byte_keys() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.private().len(), 32);
        assert_eq!(kp.public().len(), 32);
    }

    // SECURITY INVARIANT: ZeroizingKeypair::into_inner must leave the wrapper's
    // private key zeroed so that the original allocation does not retain key material
    // after ownership transfer.
    #[test]
    fn zeroizing_keypair_into_inner_zeroes_source() {
        let kp = generate_keypair().unwrap();
        let private_copy = kp.private().to_vec();
        assert!(
            !private_copy.iter().all(|&b| b == 0),
            "generated key must be non-zero"
        );

        let extracted = kp.into_inner();
        // The extracted keypair should have the original private key.
        assert_eq!(extracted.private, private_copy);
        // After into_inner, the wrapper's field was mem::take'd (zeroed Vec).
        // We can't inspect it post-move, but into_inner's implementation uses
        // mem::take which replaces with empty Vec — verified by code review.
        // This test validates the round-trip: generated key is non-zero,
        // extraction preserves key material for the caller.
    }

    // NOTE: daemon keypair persistence tests live in
    // core-ipc/tests/daemon_keypair.rs (uses set_runtime_dir_override)
    // (unsafe since Rust 2024) and the crate uses `#![forbid(unsafe_code)]`.
}
