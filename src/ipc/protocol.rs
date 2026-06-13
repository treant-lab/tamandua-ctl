//! IPC message protocol implementation
//!
//! Wire format:
//! - 4 bytes: Message length (little-endian u32)
//! - N bytes: MessagePack-encoded message

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use super::{IpcMessage, MAX_MESSAGE_SIZE};

/// Message framing helper
pub struct MessageFrame;

impl MessageFrame {
    /// Read a framed message from an async reader
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<IpcMessage> {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .context("Failed to read message length")?;

        let msg_len = u32::from_le_bytes(len_buf) as usize;

        // Validate message size
        if msg_len == 0 {
            bail!("Received zero-length message");
        }
        if msg_len > MAX_MESSAGE_SIZE {
            bail!(
                "Message too large: {} bytes (max: {})",
                msg_len,
                MAX_MESSAGE_SIZE
            );
        }

        // Read message body
        let mut msg_buf = vec![0u8; msg_len];
        reader
            .read_exact(&mut msg_buf)
            .await
            .context("Failed to read message body")?;

        // Deserialize message
        let message: IpcMessage =
            rmp_serde::from_slice(&msg_buf).context("Failed to deserialize IPC message")?;

        trace!("Received IPC message: {:?}", message);
        Ok(message)
    }

    /// Write a framed message to an async writer
    pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, message: &IpcMessage) -> Result<()> {
        // Serialize message
        let msg_bytes = rmp_serde::to_vec(message).context("Failed to serialize IPC message")?;

        let msg_len = msg_bytes.len();
        if msg_len > MAX_MESSAGE_SIZE {
            bail!(
                "Message too large: {} bytes (max: {})",
                msg_len,
                MAX_MESSAGE_SIZE
            );
        }

        // Write length prefix
        let len_bytes = (msg_len as u32).to_le_bytes();
        writer
            .write_all(&len_bytes)
            .await
            .context("Failed to write message length")?;

        // Write message body
        writer
            .write_all(&msg_bytes)
            .await
            .context("Failed to write message body")?;

        writer.flush().await.context("Failed to flush writer")?;

        trace!("Sent IPC message: {:?}", message);
        Ok(())
    }
}
