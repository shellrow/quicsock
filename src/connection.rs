//! This module contains the `QuicConnection` struct, which is used to manage the state of a QUIC connection.

use anyhow::Result;
use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A QUIC connection that can be used to send and receive data.
/// 
/// This struct wraps a `quinn::Connection` and provides a higher-level API for sending and receiving data.
/// 
/// This is used to manage the state of a QUIC connection, including the state of the send and receive streams.
pub struct QuicConnection {
    pub connection: Connection,
    send_streams: Arc<Mutex<HashMap<u64, SendStream>>>,
    recv_streams: Arc<Mutex<HashMap<u64, RecvStream>>>,
    stream_id_counter: Arc<Mutex<u64>>,
}

impl QuicConnection {
    /// Creates a new QUIC connection with the given `quinn::Connection`.
    pub async fn new(connection: Connection) -> Result<Self> {
        Ok(Self {
            connection,
            send_streams: Arc::new(Mutex::new(HashMap::new())),
            recv_streams: Arc::new(Mutex::new(HashMap::new())),
            stream_id_counter: Arc::new(Mutex::new(0)),
        })
    }
    /// Opens a new bi-directional stream on the connection.
    pub async fn open_bi_stream(&self) -> Result<u64> {
        let (send_stream, recv_stream) = self.connection.open_bi().await?;
        let mut send_streams = self.send_streams.lock().await;
        let mut recv_streams = self.recv_streams.lock().await;
        let mut stream_id_counter = self.stream_id_counter.lock().await;
        let stream_id = *stream_id_counter;
        *stream_id_counter += 1;
        send_streams.insert(stream_id, send_stream);
        recv_streams.insert(stream_id, recv_stream);
        tracing::info!("Opened bi-directional stream with ID: {}", stream_id);
        Ok(stream_id)
    }
    /// Accepts a new bi-directional stream on the connection.
    pub async fn accept_bi_stream(&self) -> Result<u64> {
        let (send_stream, recv_stream) = self.connection.accept_bi().await?;
        let mut send_streams = self.send_streams.lock().await;
        let mut recv_streams = self.recv_streams.lock().await;
        let mut stream_id_counter = self.stream_id_counter.lock().await;
        let stream_id = *stream_id_counter;
        *stream_id_counter += 1;
        send_streams.insert(stream_id, send_stream);
        recv_streams.insert(stream_id, recv_stream);
        tracing::info!("Accepted bi-directional stream with ID: {}", stream_id);
        Ok(stream_id)
    }
    /// Sends data on a certain stream.
    pub async fn send(&self, stream_id: u64, data: &[u8]) -> Result<()> {
        let mut send_streams = self.send_streams.lock().await;
        if let Some(send_stream) = send_streams.get_mut(&stream_id) {
            tracing::info!("Sending data on stream ID: {}", stream_id);
            let chunk_size = 1024;
            let mut offset = 0;
            while offset < data.len() {
                let end = std::cmp::min(offset + chunk_size, data.len());
                send_stream.write_chunk(bytes::Bytes::copy_from_slice(&data[offset..end])).await?;
                offset = end;
            }
            send_stream.flush().await?;
            send_stream.finish()?;
            // Wait for stream to close
            _ = send_stream.stopped().await;
            tracing::info!("Finished sending data on stream ID: {}", stream_id);
        }
        Ok(())
    }
    /// Receives data on a certain stream.
    pub async fn receive(&self, stream_id: u64) -> Result<Vec<u8>> {
        let mut recv_streams = self.recv_streams.lock().await;
        if let Some(recv_stream) = recv_streams.get_mut(&stream_id) {
            tracing::info!("Receiving data on stream ID: {}", stream_id);
            let mut buffer = Vec::new();
            let chunk_size = 1024;
            loop {
                match recv_stream.read_chunk(chunk_size, true).await {
                    Ok(Some(chunk)) => {
                        buffer.extend_from_slice(&chunk.bytes);
                    },
                    Ok(None) => {
                        tracing::debug!("stream end detected");
                        break;
                    },
                    Err(e) => {
                        tracing::error!("failed to read chunk: {}", e);
                        return Err(e.into());
                    },
                }
            }
            tracing::info!("Finished receiving data on stream ID: {}", stream_id);
            return Ok(buffer);
        }
        Ok(Vec::new())
    }
    /// Closes the connection.
    pub async fn close(&self) {
        self.connection.close(0u32.into(), b"done");
    }
}
