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

// ============================================================================
// Focus Monitor (wlr-foreign-toplevel-management-v1)
// ============================================================================

/// Monitors the focused (activated) toplevel via wlr-foreign-toplevel-management-v1.
///
/// Connects to the Wayland display, binds the wlr foreign toplevel manager,
/// tracks toplevel state events, and sends the `app_id` of the activated
/// toplevel through the channel whenever focus changes.
///
/// Compatible with: sway, Hyprland, niri, Wayfire, COSMIC (which also
/// advertises the wlr protocol for backwards compatibility).
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn focus_monitor(tx: tokio::sync::mpsc::Sender<String>) {
    if let Err(e) = focus_monitor_inner(&tx).await {
        tracing::warn!(error = %e, "focus monitor exiting");
    }
}

async fn focus_monitor_inner(
    tx: &tokio::sync::mpsc::Sender<String>,
) -> core_types::Result<()> {
    use std::collections::HashMap;
    use std::os::unix::io::AsFd;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use wayland_client::{
        Connection, Dispatch, EventQueue, Proxy, QueueHandle,
        globals::{GlobalList, GlobalListContents, registry_queue_init},
        protocol::wl_registry,
    };
    use wayland_protocols_wlr::foreign_toplevel::v1::client::{
        zwlr_foreign_toplevel_handle_v1::{self, ZwlrForeignToplevelHandleV1},
        zwlr_foreign_toplevel_manager_v1::{self, ZwlrForeignToplevelManagerV1},
    };

    // -- Per-toplevel tracking state --
    #[derive(Debug, Default, Clone)]
    struct ToplevelData {
        app_id: String,
        activated: bool,
    }

    // -- Wayland dispatch state --
    struct FocusState {
        toplevels: HashMap<wayland_client::backend::ObjectId, ToplevelData>,
        focused_app_id: String,
        tx: tokio::sync::mpsc::Sender<String>,
    }

    // UserData attached to each toplevel handle proxy (unit — state tracked in FocusState).
    #[derive(Debug, Default, Clone)]
    struct HandleData;

    // -- Dispatch for wl_registry (required by registry_queue_init) --
    impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for FocusState {
        fn event(
            _: &mut Self,
            _: &wl_registry::WlRegistry,
            _: wl_registry::Event,
            _: &GlobalListContents,
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
        }
    }

    // -- Dispatch for the manager: handles `toplevel` and `finished` events --
    impl Dispatch<ZwlrForeignToplevelManagerV1, ()> for FocusState {
        fn event(
            _state: &mut Self,
            _proxy: &ZwlrForeignToplevelManagerV1,
            event: zwlr_foreign_toplevel_manager_v1::Event,
            _: &(),
            _conn: &Connection,
            _qh: &QueueHandle<Self>,
        ) {
            match event {
                zwlr_foreign_toplevel_manager_v1::Event::Toplevel { toplevel: _ } => {
                    // New toplevel created — handle events arrive on the handle dispatch.
                }
                zwlr_foreign_toplevel_manager_v1::Event::Finished => {
                    tracing::info!("wlr foreign toplevel manager finished");
                }
                _ => {}
            }
        }

        wayland_client::event_created_child!(FocusState, ZwlrForeignToplevelManagerV1, [
            zwlr_foreign_toplevel_manager_v1::EVT_TOPLEVEL_OPCODE =>
                (ZwlrForeignToplevelHandleV1, HandleData)
        ]);
    }

    // -- Dispatch for individual toplevel handles --
    impl Dispatch<ZwlrForeignToplevelHandleV1, HandleData> for FocusState {
        fn event(
            state: &mut Self,
            handle: &ZwlrForeignToplevelHandleV1,
            event: zwlr_foreign_toplevel_handle_v1::Event,
            _data: &HandleData,
            _conn: &Connection,
            _qh: &QueueHandle<Self>,
        ) {
            let id = handle.id();
            match event {
                zwlr_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                    // Pending until `done`.
                    let entry = state.toplevels.entry(id).or_default();
                    entry.app_id = app_id;
                }
                zwlr_foreign_toplevel_handle_v1::Event::State { state: state_bytes } => {
                    // State is a packed array of u32 in native endian.
                    let activated = state_bytes
                        .chunks_exact(4)
                        .flat_map(TryInto::<[u8; 4]>::try_into)
                        .map(u32::from_ne_bytes)
                        .any(|v| v == zwlr_foreign_toplevel_handle_v1::State::Activated as u32);

                    let entry = state.toplevels.entry(id).or_default();
                    entry.activated = activated;
                }
                zwlr_foreign_toplevel_handle_v1::Event::Done => {
                    // Atomic commit point — check if the activated app changed.
                    if let Some(entry) = state.toplevels.get(&id)
                        && entry.activated && !entry.app_id.is_empty() && entry.app_id != state.focused_app_id {
                            state.focused_app_id.clone_from(&entry.app_id);
                            let _ = state.tx.try_send(entry.app_id.clone());
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                    let was_focused = state.toplevels.get(&id).is_some_and(|t| t.activated);
                    state.toplevels.remove(&id);
                    handle.destroy();
                    if was_focused {
                        // Focused window closed — clear focused app.
                        state.focused_app_id.clear();
                    }
                }
                // title, output_enter, output_leave, parent — not relevant for focus tracking.
                _ => {}
            }
        }
    }

    // -- Connect and bind --
    let conn = Connection::connect_to_env().map_err(|e| {
        core_types::Error::Platform(format!("Wayland connection failed: {e}"))
    })?;

    let (globals, mut event_queue): (GlobalList, EventQueue<FocusState>) =
        registry_queue_init(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

    let qh = event_queue.handle();

    // Bind the wlr foreign toplevel manager (version 3).
    let _manager: ZwlrForeignToplevelManagerV1 = globals
        .bind(&qh, 1..=3, ())
        .map_err(|e| {
            core_types::Error::Platform(format!(
                "wlr-foreign-toplevel-management-v1 not available: {e}"
            ))
        })?;

    let mut state = FocusState {
        toplevels: HashMap::new(),
        focused_app_id: String::new(),
        tx: tx.clone(),
    };

    // Initial roundtrip to receive existing toplevels.
    event_queue.roundtrip(&mut state).map_err(|e| {
        core_types::Error::Platform(format!("Wayland roundtrip failed: {e}"))
    })?;

    // -- Async event loop via tokio AsyncFd --
    let async_fd = AsyncFd::with_interest(conn.as_fd().try_clone_to_owned().map_err(|e| {
        core_types::Error::Platform(format!("failed to clone Wayland fd: {e}"))
    })?, Interest::READABLE).map_err(|e| {
        core_types::Error::Platform(format!("AsyncFd creation failed: {e}"))
    })?;

    loop {
        // Wait for the Wayland socket to become readable.
        let mut ready = async_fd.readable().await.map_err(|e| {
            core_types::Error::Platform(format!("AsyncFd readable failed: {e}"))
        })?;

        // Read events from the socket into the internal buffer.
        if let Some(guard) = conn.prepare_read() {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    return Err(core_types::Error::Platform(format!(
                        "Wayland read failed: {e}"
                    )));
                }
            }
        }

        // Dispatch all pending events to our handlers.
        event_queue.dispatch_pending(&mut state).map_err(|e| {
            core_types::Error::Platform(format!("Wayland dispatch failed: {e}"))
        })?;

        // Flush any outgoing requests (e.g. destroy).
        conn.flush().map_err(|e| {
            core_types::Error::Platform(format!("Wayland flush failed: {e}"))
        })?;

        // Clear readiness so we wait again.
        ready.clear_ready();
    }
}
