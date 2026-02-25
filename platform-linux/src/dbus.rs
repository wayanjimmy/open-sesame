//! D-Bus integration via zbus.
//!
//! Provides typed proxies for:
//! - `org.freedesktop.secrets` (Secret Service API) — secret storage
//! - `org.freedesktop.portal.GlobalShortcuts` — compositor-agnostic hotkeys
//! - Custom `org.pds.*` interfaces for daemon-to-daemon RPC over D-Bus
//!   (secondary to the postcard IPC bus; used for portal integration)
//!
//! zbus configuration: `default-features = false, features = ["tokio"]`
//! ensures no background threads — all I/O runs on the tokio runtime.
//!
//! Phase 1: type definitions only. Proxy implementations in Phase 2+ (Secrets)
//! and Phase 3+ (Input/GlobalShortcuts).

/// Connection handle wrapping a `zbus::Connection` to the session bus.
pub struct SessionBus {
    _private: (),
}

impl SessionBus {
    /// Connect to the D-Bus session bus.
    ///
    /// Phase 1: returns an error (no implementation yet).
    pub async fn connect() -> core_types::Result<Self> {
        Err(core_types::Error::Platform(
            "D-Bus session bus connection not yet implemented (Phase 2)".into(),
        ))
    }
}

/// Secret Service proxy for `org.freedesktop.secrets`.
///
/// Provides JIT secret resolution: open session, unlock collection,
/// retrieve item by label/attribute, return as `SecureBytes`.
pub struct SecretServiceProxy {
    _private: (),
}

/// Global Shortcuts portal proxy for `org.freedesktop.portal.GlobalShortcuts`.
///
/// Compositor-agnostic global hotkey registration. Supported on COSMIC,
/// KDE Plasma 6.4+, and niri via xdg-desktop-portal.
pub struct GlobalShortcutsProxy {
    _private: (),
}
