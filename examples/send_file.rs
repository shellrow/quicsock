//! This example demonstrates how to send a file using QUIC.

mod common;
use common::format_bytes;

use anyhow::Result;
use quicsock::QuicSocket;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{fs::File, io::AsyncReadExt};
use clap::Parser;
use uuid::Uuid;

use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

/// Command line arguments for the file sender.
#[derive(Parser, Debug)]
struct Args {
    /// Path of the file to send.
    #[arg(short = 'f', long = "file", help = "Path of the file to send.", required = true)]
    file_path: PathBuf,

    /// Server address to bind to.
    //#[clap(default_value = "0.0.0.0:5000")]
    #[arg(short = 'a', long = "addr", help = "Server address to bind to.", default_value = "0.0.0.0:5000")]
    server_addr: SocketAddr,

    /// Path to the certificate file (PEM or DER format).
    #[arg(short = 'c', long = "cert", help = "Path to the certificate file (PEM or DER format).")]
    cert_path: Option<PathBuf>,

    /// Path to the private key file (PEM or DER format).
    #[arg(short = 'k', long = "key", help = "Path to the private key file (PEM or DER format).")]
    key_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::DEBUG)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    // Parse command line arguments
    let args = Args::parse();

    info!("Starting file sender...");

    // Create a server socket
    let (server_socket, mut incoming_connections) = match QuicSocket::new_server(args.server_addr, args.cert_path.as_deref(), args.key_path.as_deref()).await {
        Ok((socket, incoming)) => (socket, incoming),
        Err(e) => {
            error!("Failed to create server socket: {}", e);
            return Err(anyhow::Error::msg("Failed to create server socket"));
        },
    };

    // Create a unique ID for the file
    let unique_id = Uuid::new_v4().to_string();
    println!("Share this ID with the receiver: {}", unique_id);

    // Accept incoming connections
    if let Some(connection) = server_socket.accept(&mut incoming_connections).await {
        // Accept the bi-directional stream and receive the request ID
        let stream_id = connection.accept_bi_stream().await?;
        let request_data = server_socket.receive(&connection, stream_id).await?;
        let token = String::from_utf8(request_data).unwrap();
        info!("Received request token: {}", token);
        if token == unique_id {
            // Read the file data
            let mut file = File::open(&args.file_path).await?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).await?;
            // print file name and size
            println!("File name: {}", args.file_path.file_name().unwrap().to_str().unwrap());
            println!("File size: {} bytes", buffer.len());
            // Send the file data
            info!("Sending file...");
            let start_time = std::time::Instant::now();
            let stream_id = connection.open_bi_stream().await?;
            connection.send(stream_id, &buffer).await?;
            let elapsed_time = start_time.elapsed();
            info!("File sent in: {:?}", elapsed_time);
            // Calculate bps
            let bps = buffer.len() as f64 / elapsed_time.as_secs_f64();
            println!("Speed: {}ps", format_bytes(bps as usize));
        } else {
            error!("Received request ID does not match.");
        }
    } else {
        error!("No connection received.");
    }

    Ok(())
}
