//! Length-prefixed postcard frame encoding/decoding.
//!
//! Wire format: `[4-byte big-endian payload length][postcard-encoded payload]`

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum frame payload size (16 MiB). Prevents OOM from malformed length prefixes.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Encode a value into a length-prefixed frame.
///
/// # Errors
///
/// Returns an error if postcard serialization fails.
pub fn encode_frame<T: Serialize>(value: &T) -> core_types::Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)
        .map_err(|e| core_types::Error::Ipc(format!("serialization failed: {e}")))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| core_types::Error::Ipc("payload exceeds u32 length".into()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a value from a postcard-encoded payload (without length prefix).
///
/// # Errors
///
/// Returns an error if postcard deserialization fails.
pub fn decode_frame<T: DeserializeOwned>(payload: &[u8]) -> core_types::Result<T> {
    postcard::from_bytes(payload)
        .map_err(|e| core_types::Error::Ipc(format!("deserialization failed: {e}")))
}

/// Read a single length-prefixed frame from an async reader.
///
/// # Errors
///
/// Returns an error on I/O failure or if the frame size exceeds `MAX_FRAME_SIZE`.
pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> core_types::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(core_types::Error::Ipc(format!(
            "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a single length-prefixed frame to an async writer.
///
/// # Errors
///
/// Returns an error on I/O failure.
pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> core_types::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| core_types::Error::Ipc("payload exceeds u32 length".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_types::{DaemonId, EventKind, SecurityLevel};
    use uuid::Uuid;

    #[test]
    fn encode_decode_roundtrip() {
        let event = EventKind::DaemonStarted {
            daemon_id: DaemonId::from_uuid(Uuid::from_u128(1)),
            version: "0.1.0".into(),
            capabilities: vec!["test".into()],
        };
        let msg = crate::message::Message::new(
            DaemonId::from_uuid(Uuid::from_u128(1)),
            event,
            SecurityLevel::Internal,
            std::time::Instant::now(),
        );
        let frame = encode_frame(&msg).unwrap();
        // First 4 bytes are length
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
        let decoded: crate::message::Message<EventKind> = decode_frame(&frame[4..]).unwrap();
        assert!(matches!(decoded.payload, EventKind::DaemonStarted { .. }));
    }

    #[tokio::test]
    async fn async_read_write_roundtrip() {
        let payload = b"hello postcard";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).await.unwrap();
        let mut cursor = &buf[..];
        let decoded = read_frame(&mut cursor).await.unwrap();
        assert_eq!(decoded, payload);
    }
}
