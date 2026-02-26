//! IPC message envelope.

use core_types::{DaemonId, SecurityLevel, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Instant;
use uuid::Uuid;

/// The IPC bus message envelope wrapping any payload type.
///
/// Debug is manually implemented to delegate to `T`'s Debug impl.
/// When `T = EventKind`, the payload's custom Debug redacts secret fields.
#[derive(Clone, Serialize, Deserialize)]
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

impl<T: fmt::Debug> fmt::Debug for Message<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("msg_id", &self.msg_id)
            .field("correlation_id", &self.correlation_id)
            .field("sender", &self.sender)
            .field("security_level", &self.security_level)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
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
