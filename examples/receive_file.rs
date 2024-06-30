//! This example demonstrates how to receive a file using QUIC.

mod common;
use common::format_bytes;

use anyhow::Result;
use quicsock::QuicSocket;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::{fs::File, io::AsyncWriteExt};
use clap::Parser;

use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

/// Command line arguments for the file receiver.
#[derive(Parser, Debug)]
struct Args {
    /// Path where the received file should be saved.
    #[arg(short = 's', long = "save", help = "Path where the received file should be saved.", required = true)]
    save_path: PathBuf,
    /// Unique ID to identify the file to be received.
    #[arg(short = 't', long = "token", help = "Unique ID to identify the file to be received.", required = true)]
    token: String,
    /// Server address to connect to.
    //#[clap(default_value = "127.0.0.1:5000")]
    #[arg(short = 'a', long = "addr", help = "Server address to connect to.", default_value = "127.0.0.1:5000")]
    server_addr: SocketAddr,
    /// Server name to validate the certificate against.
    #[arg(short = 'n', long = "name", help = "Server name to validate the certificate against.")]
    server_name: Option<String>,
    /// Insecure mode to skip certificate verification.
    #[arg(short, long, help = "Insecure mode to skip certificate verification.")]
    insecure: bool,
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

    // Create a client socket
    let client_socket = if args.insecure {
        match QuicSocket::new_insecure_client("0.0.0.0:0".parse().unwrap()).await {
            Ok(socket) => socket,
            Err(e) => {
                error!("Failed to create client socket: {}", e);
                return Err(anyhow::Error::msg("Failed to create client socket"));
            },
        }
    } else {
        match QuicSocket::new_native_client("0.0.0.0:0".parse().unwrap()).await {
            Ok(socket) => socket,
            Err(e) => {
                error!("Failed to create client socket: {}", e);
                return Err(anyhow::Error::msg("Failed to create client socket"));
            },
        }
    };

    // Connect to the server
    let connection = if let Some(server_name) = args.server_name {
        client_socket.connect(args.server_addr, &server_name).await?
    } else {
        client_socket.connect(args.server_addr, "localhost").await?
    };
    
    let stream_id = connection.open_bi_stream().await?;

    // Send the unique ID to the server
    client_socket.send(&connection, stream_id, args.token.as_bytes()).await?;

    // Receive the file data
    info!("Receiving file...");
    let start_time = std::time::Instant::now();
    let stream_id = connection.accept_bi_stream().await?;
    let data = client_socket.receive(&connection, stream_id).await?;
    let elapsed_time = start_time.elapsed();
    println!("File received in {} ms.", elapsed_time.as_millis());
    println!("File size: {} bytes", data.len());
    // Culculate bps
    let bps = data.len() as f64 / elapsed_time.as_secs_f64();
    println!("Speed: {}ps", format_bytes(bps as usize));
    // Save the received file
    let mut file = File::create(&args.save_path).await?;
    file.write_all(&data).await?;
    info!("File received and saved successfully.");

    Ok(())
}
