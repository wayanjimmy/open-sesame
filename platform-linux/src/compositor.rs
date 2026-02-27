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
pub fn detect_compositor() -> core_types::Result<Box<dyn CompositorBackend>> {
    match WlrBackend::connect() {
        Ok(backend) => Ok(Box::new(backend)),
        Err(e) => Err(core_types::Error::Platform(
            format!("no supported compositor backend: {e}"),
        )),
    }
}

/// CompositorBackend implementation using wlr-foreign-toplevel-management-v1.
///
/// Tracks all toplevels via the wlr protocol. Supports list, activate, focus,
/// and close operations. Compatible with sway, Hyprland, niri, Wayfire, and
/// COSMIC (backwards-compatible wlr advertisement).
///
/// Architecture: a dedicated dispatch thread continuously reads Wayland events
/// and updates a shared state snapshot on each `Done` event (the protocol's
/// atomic commit point). `list_windows()` reads the snapshot. `activate_window()`
/// and `close_window()` call proxy methods directly (wayland-client 0.31 proxies
/// are `Send + Sync`) and flush the shared connection.
pub struct WlrBackend {
    state: std::sync::Arc<std::sync::Mutex<WlrState>>,
    conn: wayland_client::Connection,
    seat: wayland_client::protocol::wl_seat::WlSeat,
    /// Kept alive so the protocol manager isn't dropped (which sends `stop` to compositor).
    _manager: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1,
}

/// Published snapshot of toplevel state, shared between dispatch thread and API callers.
struct WlrState {
    toplevels: std::collections::HashMap<
        WindowId,
        WlrToplevelSnapshot,
    >,
}

/// Committed toplevel state — only published after a `Done` event.
struct WlrToplevelSnapshot {
    app_id: String,
    title: String,
    activated: bool,
    /// Proxy handle for activate/close — Send+Sync in wayland-client 0.31.
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Pending per-toplevel state on the dispatch thread (before `Done` commits).
struct WlrPendingToplevel {
    window_id: WindowId,
    app_id: String,
    title: String,
    activated: bool,
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Dispatch thread state — owns the working copy of toplevels.
struct WlrDispatchState {
    pending: std::collections::HashMap<wayland_client::backend::ObjectId, WlrPendingToplevel>,
    shared: std::sync::Arc<std::sync::Mutex<WlrState>>,
}

/// User-data attached to each toplevel handle proxy (unit — state tracked in WlrDispatchState).
#[derive(Debug, Default, Clone)]
struct WlrHandleData;

// -- Dispatch impls for WlrDispatchState (module-level to satisfy non_local_definitions) --

impl wayland_client::Dispatch<wayland_client::protocol::wl_registry::WlRegistry, wayland_client::globals::GlobalListContents> for WlrDispatchState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_registry::WlRegistry, _: wayland_client::protocol::wl_registry::Event, _: &wayland_client::globals::GlobalListContents, _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

impl wayland_client::Dispatch<wayland_client::protocol::wl_seat::WlSeat, ()> for WlrDispatchState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_seat::WlSeat, _: wayland_client::protocol::wl_seat::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

impl wayland_client::Dispatch<wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1, ()> for WlrDispatchState {
    fn event(
        _state: &mut Self,
        _proxy: &wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1,
        event: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::Event,
        _: &(),
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        if let wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::Event::Finished = event {
            tracing::info!("wlr foreign toplevel manager finished");
        }
    }

    wayland_client::event_created_child!(WlrDispatchState, wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1, [
        wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::EVT_TOPLEVEL_OPCODE =>
            (wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1, WlrHandleData)
    ]);
}

impl wayland_client::Dispatch<wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1, WlrHandleData> for WlrDispatchState {
    fn event(
        state: &mut Self,
        handle: &wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
        event: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::Event,
        _data: &WlrHandleData,
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        use wayland_client::Proxy;
        use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1;
        let id = handle.id();
        match event {
            zwlr_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).app_id = app_id;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Title { title } => {
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).title = title;
            }
            zwlr_foreign_toplevel_handle_v1::Event::State { state: state_bytes } => {
                let activated = state_bytes.chunks_exact(4)
                    .flat_map(TryInto::<[u8; 4]>::try_into)
                    .map(u32::from_ne_bytes)
                    .any(|v| v == zwlr_foreign_toplevel_handle_v1::State::Activated as u32);
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).activated = activated;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point — publish to shared state.
                if let Some(tl) = state.pending.get(&id)
                    && let Ok(mut shared) = state.shared.lock()
                {
                    shared.toplevels.insert(tl.window_id, WlrToplevelSnapshot {
                        app_id: tl.app_id.clone(),
                        title: tl.title.clone(),
                        activated: tl.activated,
                        handle: tl.handle.clone(),
                    });
                }
            }
            zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                if let Some(tl) = state.pending.remove(&id)
                    && let Ok(mut shared) = state.shared.lock()
                {
                    shared.toplevels.remove(&tl.window_id);
                }
                handle.destroy();
            }
            _ => {}
        }
    }
}

impl WlrBackend {
    fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init, protocol::wl_seat};
        use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1;

        // -- Connect and bind --
        let conn = Connection::connect_to_env().map_err(|e| {
            core_types::Error::Platform(format!("Wayland connection failed: {e}"))
        })?;

        let (globals, mut event_queue) = registry_queue_init::<WlrDispatchState>(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

        let qh = event_queue.handle();

        let manager: ZwlrForeignToplevelManagerV1 = globals.bind(&qh, 1..=3, ()).map_err(|e| {
            core_types::Error::Platform(format!("wlr-foreign-toplevel-management-v1 not available: {e}"))
        })?;

        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=9, ()).map_err(|e| {
            core_types::Error::Platform(format!("wl_seat not available: {e}"))
        })?;

        let shared_state = std::sync::Arc::new(std::sync::Mutex::new(WlrState {
            toplevels: std::collections::HashMap::new(),
        }));

        let mut dispatch_state = WlrDispatchState {
            pending: std::collections::HashMap::new(),
            shared: std::sync::Arc::clone(&shared_state),
        };

        // Initial roundtrip to receive existing toplevels.
        event_queue.roundtrip(&mut dispatch_state).map_err(|e| {
            core_types::Error::Platform(format!("Wayland roundtrip failed: {e}"))
        })?;

        // Spawn dedicated dispatch thread for continuous event processing.
        let dispatch_conn = conn.clone();
        std::thread::Builder::new()
            .name("wlr-dispatch".into())
            .spawn(move || {
                wlr_dispatch_loop(dispatch_conn, event_queue, dispatch_state);
            })
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to spawn wlr dispatch thread: {e}"))
            })?;

        Ok(Self {
            state: shared_state,
            conn,
            seat,
            _manager: manager,
        })
    }
}

/// Continuous Wayland event dispatch loop running on a dedicated thread.
///
/// Uses `prepare_read()` + `libc::poll()` to efficiently wait for Wayland events
/// without busy-spinning. Dispatches events to the `WlrDispatchState` which
/// publishes committed state to the shared `WlrState` on `Done` events.
fn wlr_dispatch_loop(
    conn: wayland_client::Connection,
    mut event_queue: wayland_client::EventQueue<WlrDispatchState>,
    mut state: WlrDispatchState,
) {
    use std::os::fd::AsFd;
    use std::os::unix::io::AsRawFd;

    let mut backoff = std::time::Duration::from_millis(100);
    let max_backoff = std::time::Duration::from_secs(30);

    loop {
        // Prepare to read — if events are already buffered, this returns None
        // and we should dispatch immediately.
        if let Some(guard) = conn.prepare_read() {
            // Wait for Wayland fd to be readable (50ms timeout for graceful shutdown).
            let mut pollfd = libc::pollfd {
                fd: conn.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pollfd, 1, 50) };

            if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                match guard.read() {
                    Ok(_) => {
                        backoff = std::time::Duration::from_millis(100);
                    }
                    Err(wayland_client::backend::WaylandError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        tracing::error!(error = %e, backoff_ms = backoff.as_millis(), "wlr dispatch: Wayland read failed, backing off");
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                }
            } else {
                // Timeout or error — drop the read guard to cancel.
                drop(guard);
            }
        }

        // Dispatch all buffered events.
        if let Err(e) = event_queue.dispatch_pending(&mut state) {
            tracing::error!(error = %e, backoff_ms = backoff.as_millis(), "wlr dispatch: dispatch_pending failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        // Flush outgoing requests (e.g. destroy from Closed handling).
        if let Err(e) = conn.flush() {
            tracing::error!(error = %e, backoff_ms = backoff.as_millis(), "wlr dispatch: flush failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }
    }
}

impl CompositorBackend for WlrBackend {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let windows = state.toplevels.iter().map(|(wid, tl)| {
                Window {
                    id: *wid,
                    app_id: core_types::AppId::new(&tl.app_id),
                    title: tl.title.clone(),
                    workspace_id: WorkspaceId::new(),
                    monitor_id: core_types::MonitorId::new(),
                    geometry: Geometry { x: 0, y: 0, width: 0, height: 0 },
                    is_focused: tl.activated,
                    is_minimized: false,
                    is_fullscreen: false,
                    profile_id: core_types::ProfileId::new(),
                }
            }).collect();
            Ok(windows)
        })
    }

    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let tl = state.toplevels.get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.activate(&self.seat);
            drop(state);
            self.conn.flush().map_err(|e| {
                core_types::Error::Platform(format!("flush failed: {e}"))
            })?;
            Ok(())
        })
    }

    fn set_window_geometry(&self, _id: &WindowId, _geom: &Geometry) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("set_window_geometry not supported by wlr protocol".into()))
        })
    }

    fn move_to_workspace(&self, _id: &WindowId, _ws: &WorkspaceId) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("move_to_workspace not supported by wlr protocol".into()))
        })
    }

    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        self.activate_window(id)
    }

    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let tl = state.toplevels.get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.close();
            drop(state);
            self.conn.flush().map_err(|e| {
                core_types::Error::Platform(format!("flush failed: {e}"))
            })?;
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "wlr"
    }
}

// ============================================================================
// Focus Monitor (wlr-foreign-toplevel-management-v1)
// ============================================================================

/// Event from the focus monitor: either a focus change or a window close.
#[derive(Debug, Clone)]
pub enum FocusEvent {
    /// An app gained focus. Payload is the app_id.
    Focus(String),
    /// A window closed. Payload is the app_id (empty if unknown).
    Closed(String),
}

/// Monitors the focused (activated) toplevel via wlr-foreign-toplevel-management-v1.
///
/// Connects to the Wayland display, binds the wlr foreign toplevel manager,
/// tracks toplevel state events, and sends `FocusEvent`s through the channel
/// whenever focus changes or a window closes.
///
/// Compatible with: sway, Hyprland, niri, Wayfire, COSMIC (which also
/// advertises the wlr protocol for backwards compatibility).
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn focus_monitor(tx: tokio::sync::mpsc::Sender<FocusEvent>) {
    if let Err(e) = focus_monitor_inner(&tx).await {
        tracing::warn!(error = %e, "focus monitor exiting");
    }
}

async fn focus_monitor_inner(
    tx: &tokio::sync::mpsc::Sender<FocusEvent>,
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
        tx: tokio::sync::mpsc::Sender<FocusEvent>,
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
                            let _ = state.tx.try_send(FocusEvent::Focus(entry.app_id.clone()));
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                    let closed_app_id = state.toplevels.get(&id)
                        .map(|t| t.app_id.clone())
                        .unwrap_or_default();
                    let was_focused = state.toplevels.get(&id).is_some_and(|t| t.activated);
                    state.toplevels.remove(&id);
                    handle.destroy();
                    if was_focused {
                        state.focused_app_id.clear();
                    }
                    let _ = state.tx.try_send(FocusEvent::Closed(closed_app_id));
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
