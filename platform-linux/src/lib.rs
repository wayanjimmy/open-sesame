//! Linux API wrappers for PDS daemons.
//!
//! Provides safe Rust abstractions over evdev (input capture/injection),
//! Wayland protocols (toplevel management, layer-shell, data-control),
//! D-Bus (Secret Service, desktop portals), Landlock, and seccomp-bpf.
//!
//! Contains NO business logic. Consumed exclusively by daemon-* crates.
//!
//! The `cosmic` feature flag enables COSMIC-specific protocol support
//! (cosmic-toplevel-info-v1, cosmic-workspace). This pulls in GPL-3.0
//! dependencies — enable only when building for COSMIC desktop.

#[cfg(target_os = "linux")]
pub mod compositor;
#[cfg(target_os = "linux")]
pub mod cosmic_keys;
#[cfg(target_os = "linux")]
pub mod cosmic_theme;
#[cfg(target_os = "linux")]
pub mod clipboard;
#[cfg(target_os = "linux")]
pub mod dbus;
#[cfg(target_os = "linux")]
pub mod input;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod security;
#[cfg(target_os = "linux")]
pub mod systemd;
