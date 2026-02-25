//! Input capture and injection via evdev and uinput.
//!
//! Provides:
//! - `EvdevGrab`: exclusive grab on `/dev/input/event*` devices for input
//!   capture. Uses `evdev::Device::grab()` for EVIOCGRAB. Supports
//!   `Device::from_fd()` for privilege-separated fd passing.
//! - `UinputDevice`: virtual device creation via `/dev/uinput` for input
//!   injection. Built on `evdev::VirtualDeviceBuilder`.
//!
//! Requires `input` + `uinput` group membership (never root).
//! `/dev/uinput` access via udev rule:
//!   `KERNEL=="uinput", GROUP="uinput", MODE="0660"`
//!
//! Phase 1: type and trait definitions only. Implementations in Phase 3 (Input Foundation).

use std::path::PathBuf;

/// Handle to an evdev device with exclusive grab.
///
/// When held, the grabbed device's events are consumed exclusively by this
/// process — they do not reach the compositor or other clients. Drop releases
/// the grab.
pub struct EvdevGrab {
    _private: (),
}

/// Handle to a uinput virtual device for injecting input events.
///
/// Created via `UinputDevice::create()` which wraps
/// `evdev::VirtualDeviceBuilder`. The virtual device appears in
/// `/dev/input/` and emits events as if from physical hardware.
pub struct UinputDevice {
    _private: (),
}

/// Discovered evdev device metadata.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: PathBuf,
    pub name: String,
    pub is_keyboard: bool,
    pub is_pointer: bool,
}

/// Enumerate evdev devices under `/dev/input/`.
///
/// Phase 1: returns an empty list (no implementation yet).
pub fn enumerate_devices() -> core_types::Result<Vec<DeviceInfo>> {
    Err(core_types::Error::Platform(
        "evdev enumeration not yet implemented (Phase 3)".into(),
    ))
}
