//! IPC message envelope.

use core_types::{DaemonId, SecurityLevel, Timestamp};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

/// The IPC bus message envelope wrapping any payload type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message<T> {
    /// Unique message identifier (UUID v7 for time-ordering).
    pub msg_id: Uuid,
    /// Correlation ID for request-response patterns.
    pub correlation_id: Option<Uuid>,
    /// Sender daemon identity.
    pub sender: DaemonId,
    /// Dual-clock timestamp.
    pub timestamp: Timestamp,
    /// The event or request payload.
    pub payload: T,
    /// Access control level for this message.
    pub security_level: SecurityLevel,
}

impl<T: Serialize> Message<T> {
    /// Create a new message with a fresh UUID v7 and current timestamp.
    #[must_use]
    pub fn new(sender: DaemonId, payload: T, security_level: SecurityLevel, epoch: Instant) -> Self {
        Self {
            msg_id: Uuid::now_v7(),
            correlation_id: None,
            timestamp: Timestamp::now(epoch),
            sender,
            payload,
            security_level,
        }
    }

    /// Set a correlation ID for request-response linking.
    #[must_use]
    pub fn with_correlation(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }
}
