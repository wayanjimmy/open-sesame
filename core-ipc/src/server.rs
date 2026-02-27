//! IPC bus server — manages subscriber registrations, event routing,
//! and security level filtering over Unix domain sockets.
//!
//! The bus server lives inside `daemon-profile`. It binds a `UnixListener`,
//! accepts client connections with `UCred` authentication, and routes
//! postcard-framed messages between connected daemons.
//!
//! Every socket connection performs a Noise IK handshake before any application
//! data flows. The `bind()` method requires a mandatory keypair.

use core_types::{DaemonId, EventKind, SecurityLevel};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::framing::{decode_frame, encode_frame};
use crate::message::Message;
use crate::registry::ClearanceRegistry;
use crate::transport::{extract_ucred, local_credentials};

/// Subscription filter for event routing.
#[derive(Debug, Clone)]
pub struct SubscriptionFilter {
    /// Event kind prefix match (e.g. "Secret" matches all secret events).
    pub kind_prefix: Option<String>,
    /// Minimum security level required to receive events.
    pub min_level: SecurityLevel,
}

/// Per-connection state tracked by the bus server.
#[allow(dead_code)] // subscriptions used in future subscription-based routing
struct ConnectionState {
    daemon_id: Option<DaemonId>,
    /// Registry-verified daemon name from Noise IK handshake.
    /// `None` for unregistered clients (CLI, Open clearance).
    verified_name: Option<String>,
    tx: mpsc::Sender<Vec<u8>>,
    peer: crate::transport::PeerCredentials,
    security_clearance: SecurityLevel,
    subscriptions: Vec<SubscriptionFilter>,
}

/// Shared state for the bus server, accessible from per-connection tasks.
struct ServerState {
    connections: RwLock<HashMap<u64, ConnectionState>>,
    /// Maps request `msg_id` -> originating `connection_id` for response routing.
    pending_requests: RwLock<HashMap<Uuid, u64>>,
    next_conn_id: AtomicU64,
    epoch: Instant,
    /// Maps public keys to daemon identities and security clearance levels.
    /// `RwLock` allows key rotation (H-018) and revocation (H-019) at runtime.
    registry: RwLock<ClearanceRegistry>,
}

/// The IPC bus server.
pub struct BusServer {
    listener: Option<UnixListener>,
    socket_path: Option<PathBuf>,
    state: Arc<ServerState>,
    /// Noise IK static keypair for the bus server.
    /// Always `Some` from `bind()`. `None` only from `new()` (channel-wired mode).
    keypair: Option<Arc<snow::Keypair>>,
}

impl BusServer {
    /// Create a new bus server without a listener (for in-process channel wiring).
    ///
    /// Used only for `register()`/`unregister()` based in-process testing where
    /// clients are pre-wired via channels rather than socket connections.
    /// Does NOT support socket accept — use `bind()` for socket-based servers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            listener: None,
            socket_path: None,
            state: Arc::new(ServerState {
                connections: RwLock::new(HashMap::new()),
                pending_requests: RwLock::new(HashMap::new()),
                next_conn_id: AtomicU64::new(1),
                epoch: Instant::now(),
                registry: RwLock::new(ClearanceRegistry::new()),
            }),
            keypair: None,
        }
    }

    /// Bind a Unix domain socket listener at the given path.
    ///
    /// The `keypair` is the server's Noise IK static keypair (mandatory),
    /// used to perform encrypted handshakes with connecting clients. Generated
    /// via [`crate::generate_keypair()`] and published via
    /// [`crate::noise::write_bus_keypair()`].
    ///
    /// Creates the parent directory if it does not exist. Removes any stale
    /// socket file at the path before binding.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or socket binding fails.
    pub fn bind(path: &Path, keypair: snow::Keypair, registry: ClearanceRegistry) -> core_types::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                core_types::Error::Ipc(format!(
                    "failed to create socket directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Remove stale socket if it exists.
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                core_types::Error::Ipc(format!(
                    "failed to remove stale socket {}: {e}",
                    path.display()
                ))
            })?;
        }

        let listener = UnixListener::bind(path).map_err(|e| {
            core_types::Error::Ipc(format!(
                "failed to bind socket {}: {e}",
                path.display()
            ))
        })?;

        // Defense-in-depth: restrict socket and parent directory permissions to owner-only.
        // UCred UID validation is the real security boundary, but this hardens against
        // misconfigured XDG_RUNTIME_DIR permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = path.parent() {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| {
                        core_types::Error::Ipc(format!(
                            "failed to set directory permissions on {}: {e}",
                            parent.display()
                        ))
                    })?;
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    core_types::Error::Ipc(format!(
                        "failed to set socket permissions on {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        tracing::info!(path = %path.display(), "IPC bus server bound");

        Ok(Self {
            listener: Some(listener),
            socket_path: Some(path.to_owned()),
            state: Arc::new(ServerState {
                connections: RwLock::new(HashMap::new()),
                pending_requests: RwLock::new(HashMap::new()),
                next_conn_id: AtomicU64::new(1),
                epoch: Instant::now(),
                registry: RwLock::new(registry),
            }),
            keypair: Some(Arc::new(keypair)),
        })
    }

    /// Run the accept loop. This future never completes unless the listener
    /// encounters a fatal error. Cancel it via `tokio::select!` with a
    /// shutdown signal.
    ///
    /// # Errors
    ///
    /// Returns an error if no listener was bound (created via `new()` instead
    /// of `bind()`).
    ///
    /// # Panics
    ///
    /// Panics if called on a `BusServer` created via `bind()` whose keypair
    /// was somehow removed (should be unreachable).
    pub async fn run(&self) -> core_types::Result<()> {
        let listener = self.listener.as_ref().ok_or_else(|| {
            core_types::Error::Ipc("BusServer::run() called without bind()".into())
        })?;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let peer = match extract_ucred(&stream) {
                        Ok(creds) => creds,
                        Err(e) => {
                            tracing::error!(error = %e, "rejecting connection: UCred extraction failed");
                            continue;
                        }
                    };

                    // Enforce same-UID policy: only the owning user may connect.
                    let my_uid = local_credentials().uid;
                    if peer.uid != my_uid {
                        tracing::error!(
                            peer_uid = peer.uid,
                            my_uid,
                            "rejecting connection: UID mismatch"
                        );
                        continue;
                    }

                    let conn_id = self.state.next_conn_id.fetch_add(1, Ordering::Relaxed);

                    tracing::info!(
                        conn_id,
                        pid = peer.pid,
                        uid = peer.uid,
                        "client connected"
                    );

                    // Per-connection outbound channel (server -> client).
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

                    let state = Arc::clone(&self.state);
                    let keypair = self.keypair.clone()
                        .expect("BusServer::run() requires bind() — keypair is always set");
                    tokio::spawn(async move {
                        handle_connection(state, conn_id, stream, tx, rx, peer, keypair).await;
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, "accept failed");
                    // Transient errors: continue. Fatal errors would typically
                    // be caught by the OS (e.g. too many open files).
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Register a subscriber with pre-wired channels (for in-process testing).
    pub async fn register(
        &self,
        daemon_id: DaemonId,
        peer: crate::transport::PeerCredentials,
        security_clearance: SecurityLevel,
        subscriptions: Vec<SubscriptionFilter>,
        tx: mpsc::Sender<Vec<u8>>,
    ) {
        let conn_id = self.state.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let state = ConnectionState {
            daemon_id: Some(daemon_id),
            verified_name: None, // In-process subscribers have no Noise handshake.
            tx,
            security_clearance,
            subscriptions,
            peer,
        };
        self.state.connections.write().await.insert(conn_id, state);
        tracing::info!(%daemon_id, conn_id, "subscriber registered (in-process)");
    }

    /// Remove a subscriber by daemon ID.
    pub async fn unregister(&self, daemon_id: &DaemonId) {
        let mut conns = self.state.connections.write().await;
        conns.retain(|_, state| {
            state.daemon_id.as_ref() != Some(daemon_id)
        });
        tracing::info!(%daemon_id, "subscriber unregistered");
    }

    /// Publish an already-encoded frame to all matching subscribers.
    pub async fn publish(&self, frame: &[u8], security_level: SecurityLevel) {
        let conns = self.state.connections.read().await;
        for (id, state) in conns.iter() {
            if state.security_clearance >= security_level
                && state.tx.try_send(frame.to_vec()).is_err()
            {
                tracing::warn!(conn_id = id, "subscriber channel full, frame dropped");
            }
        }
    }

    /// Return the server's monotonic epoch for timestamp generation.
    #[must_use]
    pub fn epoch(&self) -> Instant {
        self.state.epoch
    }

    /// Return the socket path if bound.
    #[must_use]
    pub fn socket_path(&self) -> Option<&Path> {
        self.socket_path.as_deref()
    }

    /// Return the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.state.connections.read().await.len()
    }

    /// Send a frame to a specific connection by ID (unicast).
    ///
    /// Returns `true` if the frame was enqueued, `false` if the connection
    /// was not found or its channel was full.
    pub async fn send_to(&self, conn_id: u64, frame: &[u8]) -> bool {
        let conns = self.state.connections.read().await;
        if let Some(conn) = conns.get(&conn_id) {
            conn.tx.try_send(frame.to_vec()).is_ok()
        } else {
            false
        }
    }

    /// Access the clearance registry for mutation (key rotation H-018, revocation H-019).
    pub async fn registry_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, ClearanceRegistry> {
        self.state.registry.write().await
    }

    /// Look up and remove the originating connection for a correlated response.
    ///
    /// When a request arrives via `route_frame()`, the server records
    /// `(msg_id -> sender_conn_id)` in `pending_requests`. This method
    /// retrieves and removes that mapping so the response can be unicast
    /// back to the original requester instead of broadcast.
    pub async fn take_pending_request(&self, correlation_id: &uuid::Uuid) -> Option<u64> {
        self.state.pending_requests.write().await.remove(correlation_id)
    }
}

impl Default for BusServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BusServer {
    fn drop(&mut self) {
        // Clean up the socket file.
        if let Some(path) = &self.socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Hex-encode a 32-byte key for logging. No `hex` crate dependency needed.
fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Handle a single client connection: perform Noise handshake, then read/write encrypted frames.
///
/// The connection is registered in `state.connections` only AFTER the handshake
/// succeeds. This prevents the race where broadcast frames arrive on the
/// outbound channel before the writer task (which needs the `NoiseTransport`)
/// is spawned.
#[allow(clippy::too_many_lines)]
async fn handle_connection(
    state: Arc<ServerState>,
    conn_id: u64,
    stream: UnixStream,
    tx: mpsc::Sender<Vec<u8>>,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    peer_creds: crate::transport::PeerCredentials,
    keypair: Arc<snow::Keypair>,
) {
    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    // Perform Noise IK handshake — mandatory for all socket connections.
    let local_creds = local_credentials();
    let connected_at = Instant::now();

    let mut transport = match crate::noise::server_handshake(
        &mut reader,
        &mut writer,
        &keypair,
        &local_creds,
        &peer_creds,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            // H-015: structured handshake failure audit.
            tracing::error!(
                audit = "connection-lifecycle",
                event_type = "handshake-failed",
                conn_id,
                peer_pid = peer_creds.pid,
                peer_uid = peer_creds.uid,
                error = %e,
                "Noise handshake failed, dropping connection"
            );
            return;
        }
    };

    // Extract client's X25519 static public key from completed Noise IK handshake.
    let client_pubkey: [u8; 32] = transport
        .remote_static()
        .expect("Noise IK pattern guarantees remote static key after handshake")
        .try_into()
        .expect("Curve25519 public key is exactly 32 bytes");

    // Registry lookup: cryptographic identity -> (name, clearance).
    // H-021: capture verified_name for sender identity verification.
    let (security_clearance, verified_name) = {
        let reg = state.registry.read().await;
        if let Some(entry) = reg.lookup(&client_pubkey) {
            tracing::info!(
                audit = "connection-lifecycle",
                event_type = "handshake-success",
                conn_id,
                daemon = %entry.name,
                clearance = ?entry.security_level,
                pubkey = %hex_encode(&client_pubkey),
                peer_pid = peer_creds.pid,
                peer_uid = peer_creds.uid,
                "daemon authenticated via registry"
            );
            (entry.security_level, Some(entry.name.clone()))
        } else {
            tracing::info!(
                conn_id,
                pubkey = %hex_encode(&client_pubkey),
                "unregistered public key — assigning SecretsOnly clearance (Noise-authenticated, same-UID)"
            );
            (SecurityLevel::SecretsOnly, None)
        }
    };

    // Register connection AFTER handshake succeeds — no frames can arrive
    // on `tx` before the writer task is ready to handle them.
    let conn = ConnectionState {
        daemon_id: None,
        verified_name,
        tx,
        peer: peer_creds,
        security_clearance,
        subscriptions: vec![],
    };
    state.connections.write().await.insert(conn_id, conn);

    // Single-task multiplexed I/O for encrypted transport.
    //
    // snow::TransportState requires &mut self for both encrypt and decrypt,
    // so we cannot split it between separate reader/writer tasks without a
    // Mutex. But the reader would hold the lock while awaiting socket I/O,
    // starving the writer (deadlock). Instead, we use tokio::select! to
    // multiplex reads and writes in a single task that owns the transport.
    loop {
        tokio::select! {
            result = transport.read_encrypted_frame(&mut reader) => {
                match result {
                    Ok(mut payload) => {
                        route_frame(&state, conn_id, &payload).await;
                        // Zeroize decrypted postcard buffer — may contain secret values (H-009).
                        zeroize::Zeroize::zeroize(&mut payload);
                    }
                    Err(e) => {
                        let session_ms = connected_at.elapsed().as_millis();
                        let daemon_name = state.connections.read().await
                            .get(&conn_id)
                            .and_then(|c| c.daemon_id)
                            .map(|id| id.to_string());
                        tracing::info!(
                            audit = "connection-lifecycle",
                            event_type = "disconnect",
                            conn_id,
                            daemon = daemon_name.as_deref().unwrap_or("unknown"),
                            session_duration_ms = %session_ms,
                            error = %e,
                            "client disconnected"
                        );
                        break;
                    }
                }
            }
            Some(mut payload) = outbound_rx.recv() => {
                let result = transport.write_encrypted_frame(&mut writer, &payload).await;
                // Zeroize plaintext postcard buffer after encryption (H-009).
                zeroize::Zeroize::zeroize(&mut payload);
                if let Err(e) = result {
                    tracing::debug!(conn_id, error = %e, "encrypted write failed, closing");
                    break;
                }
            }
            else => break,
        }
    }

    state.connections.write().await.remove(&conn_id);
    state.pending_requests.write().await.retain(|_, cid| *cid != conn_id);
    let session_ms = connected_at.elapsed().as_millis();
    tracing::debug!(
        audit = "connection-lifecycle",
        event_type = "cleanup",
        conn_id,
        session_duration_ms = %session_ms,
        "connection cleaned up"
    );
}

/// Send an `AccessDenied` error response back to the sender so the client
/// gets an actionable error instead of a silent timeout.
fn send_access_denied(
    conn: &ConnectionState,
    request_msg_id: Uuid,
    epoch: Instant,
    reason: String,
) {
    let reply = Message::new(
        DaemonId::new(),
        EventKind::AccessDenied { reason },
        SecurityLevel::Open,
        epoch,
    )
    .with_correlation(request_msg_id);

    if let Ok(reply_bytes) = encode_frame(&reply) {
        let _ = conn.tx.try_send(reply_bytes);
    }
}

/// Route a received frame to the appropriate destination(s).
///
/// - If the message has a `correlation_id`, it's a response — route only to
///   the connection that originated the request.
/// - Otherwise, it's a new request or broadcast — record the `msg_id` for
///   response routing and forward to all other subscribers.
#[allow(clippy::too_many_lines)]
async fn route_frame(state: &ServerState, sender_conn_id: u64, payload: &[u8]) {
    // Decode the message header to extract routing information.
    let mut msg: Message<EventKind> = match decode_frame(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(conn_id = sender_conn_id, error = %e, "malformed frame, dropping");
            return;
        }
    };

    // Update daemon_id, enforce sender clearance, and capture verified_name
    // in a single lock acquisition to prevent TOCTOU.
    let verified_name: Option<String>;
    {
        let mut conns = state.connections.write().await;
        if let Some(conn) = conns.get_mut(&sender_conn_id) {
            // H-021: Sender identity verification (NIST IA-9, SC-23).
            // First message: record the self-declared DaemonId.
            // Subsequent messages: verify consistency — a connection must not
            // change its DaemonId mid-session (impersonation attempt).
            if let Some(known_id) = conn.daemon_id {
                if known_id != msg.sender {
                    tracing::warn!(
                        audit = "security",
                        event_type = "sender-identity-mismatch",
                        conn_id = sender_conn_id,
                        expected_sender = %known_id,
                        claimed_sender = %msg.sender,
                        verified_name = conn.verified_name.as_deref().unwrap_or("unregistered"),
                        "sender DaemonId changed mid-session, dropping frame"
                    );
                    send_access_denied(
                        conn,
                        msg.msg_id,
                        state.epoch,
                        "sender identity changed mid-session".into(),
                    );
                    return;
                }
            } else {
                conn.daemon_id = Some(msg.sender);

                // Log the binding between verified name and self-declared DaemonId.
                if let Some(ref name) = conn.verified_name {
                    tracing::info!(
                        audit = "identity-binding",
                        conn_id = sender_conn_id,
                        daemon_name = %name,
                        daemon_id = %msg.sender,
                        "daemon identity bound: registry name <-> self-declared DaemonId"
                    );
                }
            }

            // Sender clearance enforcement (NIST AC-4, AC-6): a daemon may only
            // emit messages at or below its own clearance level. This prevents a
            // compromised low-clearance daemon from injecting high-clearance messages.
            if conn.security_clearance < msg.security_level {
                tracing::warn!(
                    conn_id = sender_conn_id,
                    sender_clearance = ?conn.security_clearance,
                    msg_level = ?msg.security_level,
                    "sender clearance below message security level, rejecting"
                );
                send_access_denied(
                    conn,
                    msg.msg_id,
                    state.epoch,
                    format!(
                        "sender clearance {:?} below message security level {:?}",
                        conn.security_clearance, msg.security_level,
                    ),
                );
                return;
            }

            // R-008: Capture verified_name from Noise IK registry lookup.
            verified_name = conn.verified_name.clone();
        } else {
            verified_name = None;
        }
    }

    // R-008: Stamp server-verified sender identity onto the message.
    // This prevents daemons from self-declaring any name via capabilities.
    // Re-encode after stamping so downstream receivers get the verified name.
    // Note: re-encode adds serialization overhead on every routed frame. For a
    // local IPC bus with <10 daemons this is negligible (~µs per frame).
    msg.verified_sender_name = verified_name;
    let stamped_payload = match encode_frame(&msg) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(conn_id = sender_conn_id, error = %e, "failed to re-encode stamped frame");
            return;
        }
    };

    if let Some(corr_id) = msg.correlation_id {
        // This is a response — route to the originating connection.
        let target_conn = state.pending_requests.write().await.remove(&corr_id);
        if let Some(target_id) = target_conn {
            let conns = state.connections.read().await;
            if let Some(target) = conns.get(&target_id)
                && target.tx.try_send(stamped_payload.clone()).is_err()
            {
                tracing::warn!(
                    conn_id = target_id,
                    correlation_id = %corr_id,
                    "response dropped: channel full"
                );
            }
        } else {
            tracing::debug!(
                correlation_id = %corr_id,
                "response for unknown request, dropping"
            );
        }
    } else {
        // New request or broadcast — record for response routing and forward.
        state.pending_requests.write().await.insert(msg.msg_id, sender_conn_id);

        let conns = state.connections.read().await;
        for (&cid, conn) in conns.iter() {
            if cid == sender_conn_id {
                continue; // Don't echo back to sender.
            }
            if conn.security_clearance < msg.security_level {
                continue; // Recipient clearance too low for this message.
            }
            if conn.tx.try_send(stamped_payload.clone()).is_err() {
                tracing::warn!(conn_id = cid, "subscriber channel full, frame dropped");
            }
        }
    }
}
