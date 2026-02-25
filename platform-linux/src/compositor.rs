//! Compositor backend trait and detection for Linux Wayland compositors.
//!
//! The `CompositorBackend` trait abstracts window/workspace management over
//! multiple Wayland compositor protocol sets:
//! - `cosmic-toplevel-info-v1` + `cosmic-toplevel-management-v1` (COSMIC)
//! - `wlr-foreign-toplevel-management-v1` (Hyprland, sway, niri, Wayfire)
//! - Sway/i3 IPC socket fallback
//!
//! Phase 1: trait + type definitions only. Backend implementations in Phase 2+.

use core_types::{Geometry, Window, WindowId, WorkspaceId};
use std::future::Future;
use std::pin::Pin;

/// A Wayland workspace.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub is_active: bool,
}

/// Configuration for creating a layer-shell surface.
#[derive(Debug, Clone)]
pub struct LayerSurfaceConfig {
    pub namespace: String,
    pub layer: Layer,
    pub anchor: Anchor,
    pub exclusive_zone: i32,
    pub keyboard_mode: KeyboardMode,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Wayland layer-shell layer.
#[derive(Debug, Clone, Copy)]
pub enum Layer {
    Background,
    Bottom,
    Top,
    Overlay,
}

/// Anchor edges for layer-shell surfaces.
#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    pub top: bool,
    pub right: bool,
    pub bottom: bool,
    pub left: bool,
}

/// Keyboard focus mode for layer-shell surfaces.
#[derive(Debug, Clone, Copy)]
pub enum KeyboardMode {
    None,
    Exclusive,
    OnDemand,
}

/// Opaque handle to a layer-shell surface.
pub struct LayerSurface {
    _private: (),
}

// Type alias for boxed async results used by CompositorBackend methods.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over Wayland compositor protocols for window management.
///
/// Implementations:
/// - `CosmicBackend` (cosmic-toplevel-info-v1 + cosmic-toplevel-management-v1)
/// - `WlrBackend` (wlr-foreign-toplevel-management-v1)
/// - `SwayIpcBackend` (sway/i3 IPC socket)
///
/// Uses `Pin<Box<dyn Future>>` return types for dyn-compatibility — required
/// because `detect_compositor()` returns `Box<dyn CompositorBackend>` for
/// runtime backend selection. Rust RPITIT (`-> impl Future`) is not
/// dyn-compatible.
///
/// Phase 1: trait definition only. Implementations in Phase 2+.
pub trait CompositorBackend: Send + Sync {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>>;
    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>>;
    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn set_window_geometry(
        &self,
        id: &WindowId,
        geom: &Geometry,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn move_to_workspace(
        &self,
        id: &WindowId,
        ws: &WorkspaceId,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;

    /// Human-readable backend name for diagnostics (e.g. "cosmic", "wlr", "sway-ipc").
    fn name(&self) -> &str;
}

/// Detect and instantiate the appropriate compositor backend.
///
/// Detection order:
/// 1. COSMIC-specific protocols (if `cosmic` feature enabled)
/// 2. wlr-foreign-toplevel-management-v1 (Hyprland, sway, niri)
/// 3. Sway IPC socket at `$SWAYSOCK`
/// 4. Error with available protocol listing
///
/// Phase 1: returns an error (no implementations yet).
pub fn detect_compositor() -> core_types::Result<Box<dyn CompositorBackend>> {
    Err(core_types::Error::Platform(
        "compositor detection not yet implemented (Phase 2)".into(),
    ))
}
