//! IPC bus client — connects to the bus server, publishes events,
//! and receives subscribed events.

use core_types::{DaemonId, EventKind, SecurityLevel};
use std::time::Instant;
use tokio::sync::mpsc;

use crate::framing;
use crate::message::Message;

/// The IPC bus client used by each daemon to communicate on the bus.
pub struct BusClient {
    daemon_id: DaemonId,
    /// Outbound frames to send to the server.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Inbound frames received from the server.
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    epoch: Instant,
}

impl BusClient {
    /// Create a new bus client with pre-wired channels.
    ///
    /// In production, the channels are connected to the Unix domain socket
    /// reader/writer tasks. For testing, they can be connected directly to
    /// a `BusServer`.
    #[must_use]
    pub fn new(
        daemon_id: DaemonId,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        inbound_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            daemon_id,
            outbound_tx,
            inbound_rx,
            epoch: Instant::now(),
        }
    }

    /// Publish an event to the bus.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the outbound channel is closed.
    pub async fn publish(
        &self,
        event: EventKind,
        security_level: SecurityLevel,
    ) -> core_types::Result<()> {
        let msg = Message::new(self.daemon_id, event, security_level, self.epoch);
        let frame = framing::encode_frame(&msg)?;
        // Send the raw frame (without length prefix — the transport layer adds it)
        let payload = frame[4..].to_vec();
        self.outbound_tx.send(payload).await.map_err(|_| {
            core_types::Error::Ipc("outbound channel closed".into())
        })?;
        Ok(())
    }

    /// Receive the next inbound event from the bus.
    ///
    /// Returns `None` if the inbound channel is closed (server disconnected).
    pub async fn recv(&mut self) -> Option<Message<EventKind>> {
        let frame = self.inbound_rx.recv().await?;
        match framing::decode_frame(&frame) {
            Ok(msg) => Some(msg),
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode inbound frame");
                None
            }
        }
    }

    /// Return this client's daemon ID.
    #[must_use]
    pub fn daemon_id(&self) -> DaemonId {
        self.daemon_id
    }

    /// Return the client's monotonic epoch.
    #[must_use]
    pub fn epoch(&self) -> Instant {
        self.epoch
    }
}
