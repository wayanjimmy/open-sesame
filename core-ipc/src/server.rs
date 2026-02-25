//! IPC bus server — manages subscriber registrations, event routing,
//! and security level filtering.
//!
//! The bus server lives inside `daemon-profile`. This module provides the
//! core data structures and routing logic.

use core_types::{DaemonId, SecurityLevel};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

/// Subscription filter for event routing.
#[derive(Debug, Clone)]
pub struct SubscriptionFilter {
    /// Event kind prefix match (e.g. "Window" matches all window events).
    pub kind_prefix: Option<String>,
    /// Minimum security level required to receive events.
    pub min_level: SecurityLevel,
}

/// Per-subscriber state tracked by the bus server.
struct SubscriberState {
    tx: mpsc::Sender<Vec<u8>>,
    security_clearance: SecurityLevel,
    subscriptions: Vec<SubscriptionFilter>,
    peer: crate::transport::PeerCredentials,
}

/// The IPC bus server.
pub struct BusServer {
    subscribers: Arc<RwLock<HashMap<DaemonId, SubscriberState>>>,
    epoch: Instant,
}

impl BusServer {
    /// Create a new bus server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            epoch: Instant::now(),
        }
    }

    /// Register a new subscriber with the given credentials and channel.
    pub async fn register(
        &self,
        daemon_id: DaemonId,
        peer: crate::transport::PeerCredentials,
        security_clearance: SecurityLevel,
        subscriptions: Vec<SubscriptionFilter>,
        tx: mpsc::Sender<Vec<u8>>,
    ) {
        let state = SubscriberState {
            tx,
            security_clearance,
            subscriptions,
            peer,
        };
        self.subscribers.write().await.insert(daemon_id, state);
        tracing::info!(%daemon_id, "subscriber registered");
    }

    /// Remove a subscriber.
    pub async fn unregister(&self, daemon_id: &DaemonId) {
        self.subscribers.write().await.remove(daemon_id);
        tracing::info!(%daemon_id, "subscriber unregistered");
    }

    /// Publish an already-encoded frame to all matching subscribers.
    ///
    /// Subscribers that fail to receive (full channel) are logged but not
    /// immediately disconnected — the grace period is handled by the
    /// daemon-profile accept loop.
    pub async fn publish(&self, frame: &[u8], security_level: SecurityLevel) {
        let subs = self.subscribers.read().await;
        for (id, state) in subs.iter() {
            if state.security_clearance >= security_level {
                if state.tx.try_send(frame.to_vec()).is_err() {
                    tracing::warn!(%id, "subscriber channel full, frame dropped");
                }
            }
        }
    }

    /// Return the server's monotonic epoch for timestamp generation.
    #[must_use]
    pub fn epoch(&self) -> Instant {
        self.epoch
    }
}

impl Default for BusServer {
    fn default() -> Self {
        Self::new()
    }
}
