//! QUIC socket. The main entry point for sending and receiving data over QUIC.

use anyhow::Result;
use std::{error::Error, path::Path};
use quinn::{Endpoint, Incoming};
use std::net::SocketAddr;
use tokio::sync::{mpsc, Mutex};
use crate::{connection::QuicConnection, endpoint::{make_client_endpoint, make_native_client_endpoint, make_insecure_client_endpoint, make_server_endpoint, make_self_signed_server_endpoint}};
use std::collections::HashMap;
use std::sync::Arc;

/// A QUIC socket that can be used to send and receive data.
pub struct QuicSocket {
    endpoint: Endpoint,
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<QuicConnection>>>>,
}

impl QuicSocket {
    /// Creates a new QUIC server bound to a certain address and port.
    /// 
    /// If `cert_path` and `key_path` are provided, the server will use the certificate and key at those
    /// 
    /// paths. Otherwise, a self-signed certificate will be generated.
    pub async fn new_server(addr: SocketAddr, cert_path: Option<&Path>, key_path: Option<&Path>) -> Result<(Self, mpsc::Receiver<Incoming>), Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = match make_server_endpoint(addr, cert_path, key_path) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                return Err(e);
            },
        };
        let (tx, rx) = mpsc::channel(100);
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_clone.accept().await {
                let _ = tx.send(incoming).await;
            }
        });
        tracing::info!("Server listening on: {}", addr);
        Ok((Self { endpoint, connections: Arc::new(Mutex::new(HashMap::new())) }, rx))
    }
    /// Creates a new QUIC server bound to a certain address and port.
    /// 
    /// Self-signed certificate will be generated.
    pub async fn new_self_signed_server(addr: SocketAddr) -> Result<(Self, mpsc::Receiver<Incoming>), Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = match make_self_signed_server_endpoint(addr) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                return Err(e);
            },
        };
        let (tx, rx) = mpsc::channel(100);
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint_clone.accept().await {
                let _ = tx.send(incoming).await;
            }
        });
        tracing::info!("Server listening on: {}", addr);
        Ok((Self { endpoint, connections: Arc::new(Mutex::new(HashMap::new())) }, rx))
    }
    /// Creates a new QUIC client bound to a certain address and port.
    /// 
    /// The client will use the provided server certificates to verify the server's identity.
    pub async fn new_client(bind_addr: SocketAddr, server_certs: &[&[u8]]) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = make_client_endpoint(bind_addr, server_certs)?;
        tracing::info!("Client bound to {:?}", endpoint.local_addr());
        Ok(Self { endpoint, connections: Arc::new(Mutex::new(HashMap::new())) })
    }
    /// Creates a new QUIC client bound to a certain address and port.
    /// 
    /// The client will use the root certificates found in the platform's native certificate store to verify the server's identity.
    /// 
    /// This is useful when connecting to servers that use certificates signed by a trusted CA.
    pub async fn new_native_client(bind_addr: SocketAddr) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = make_native_client_endpoint(bind_addr)?;
        tracing::info!("Client bound to {:?}", endpoint.local_addr());
        Ok(Self { endpoint, connections: Arc::new(Mutex::new(HashMap::new())) })
    }
    /// Creates a new QUIC client bound to a certain address and port.
    /// 
    /// The client will skip server certificate verification.
    /// 
    /// This is useful when connecting to servers that use self-signed certificates.
    pub async fn new_insecure_client(bind_addr: SocketAddr) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = make_insecure_client_endpoint(bind_addr)?;
        tracing::info!("Client bound to {:?}", endpoint.local_addr());
        Ok(Self { endpoint, connections: Arc::new(Mutex::new(HashMap::new())) })
    }
    /// Connects to a server at a certain address and port.
    /// 
    /// The returned connection can be used to send and receive data.
    pub async fn connect(&self, server_addr: SocketAddr, server_name: &str) -> Result<Arc<QuicConnection>> {
        let connection = self.endpoint.connect(server_addr, server_name)?.await?;
        let quic_connection = Arc::new(QuicConnection::new(connection).await?);
        self.connections.lock().await.insert(server_addr, Arc::clone(&quic_connection));
        tracing::info!("Connected to server: {}", server_addr);
        Ok(quic_connection)
    }
    /// Accepts an incoming connection.
    /// 
    /// The returned connection can be used to send and receive data.
    pub async fn accept(&self, incoming: &mut mpsc::Receiver<Incoming>) -> Option<Arc<QuicConnection>> {
        if let Some(connecting) = incoming.recv().await {
            let connection = match connecting.await {
                Ok(conn) => Arc::new(QuicConnection::new(conn).await.unwrap()),
                Err(_) => return None,
            };

            let remote_addr = connection.connection.remote_address();
            self.connections.lock().await.insert(remote_addr, Arc::clone(&connection));
            tracing::info!("Accepted connection from: {}", remote_addr);
            return Some(connection);
        }
        None
    }
    /// Sends data to a certain connection.
    /// 
    /// The data will be sent on the stream with the specified ID.
    pub async fn send(&self, connection: &QuicConnection, stream_id: u64, data: &[u8]) -> Result<()> {
        connection.send(stream_id, data).await
    }
    /// Receives data from a certain connection.
    /// 
    /// The data will be received from the stream with the specified ID.
    pub async fn receive(&self, connection: &QuicConnection, stream_id: u64) -> Result<Vec<u8>> {
        connection.receive(stream_id).await
    }
    /// Closes a certain connection.
    /// 
    /// The connection will be gracefully closed.
    pub async fn close_connection(&self, addr: &SocketAddr) {
        if let Some(conn) = self.connections.lock().await.remove(addr) {
            conn.close().await;
        }
    }
    /// Closes all connections.
    /// 
    /// All connections will be gracefully closed.
    pub async fn close_all(&self) {
        let mut connections = self.connections.lock().await;
        for conn in connections.values() {
            conn.close().await;
        }
        connections.clear();
    }
}
