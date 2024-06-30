//! Module for creating QUIC endpoints.

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::ServerCertVerifier;
use std::path::Path;
use std::sync::Arc;
use std::{error::Error, net::SocketAddr};
use quinn_proto::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig as RustlsClientConfig;

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
/// - bind_addr: the address to bind the client endpoint to.
///
/// - server_certs: list of trusted certificates.
pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Constructs a QUIC client endpoint using root certificates found in the platform's native certificate store.
pub fn make_native_client_endpoint(
    bind_addr: SocketAddr,
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let native_certs = crate::tls::certificate::get_native_certs()?;
    let rustls_client_config = RustlsClientConfig::builder().with_root_certificates(native_certs).with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client_config)?));
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Constructs a QUIC client endpoint that skips server certificate verification.
///
/// ## Args
///
/// - bind_addr: the address to bind the client endpoint to.
pub fn make_insecure_client_endpoint(
    bind_addr: SocketAddr,
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth(),
    )?)));

    Ok(endpoint)
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
/// If `cert_path` and `key_path` are provided, the server will use the certificate and key at those
/// paths. Otherwise, a self-signed certificate will be generated.
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let server_config = configure_server(cert_path, key_path)?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
pub fn make_self_signed_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let server_config = configure_self_signed_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client(
    server_certs: &[&[u8]],
) -> Result<ClientConfig, Box<dyn Error + Send + Sync + 'static>> {
    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(CertificateDer::from(*cert))?;
    }

    Ok(ClientConfig::with_root_certificates(Arc::new(certs))?)
}

/// Returns server configuration along with its certificate.
fn configure_server(cert_path: Option<&Path>, key_path: Option<&Path>) -> Result<ServerConfig, Box<dyn Error + Send + Sync + 'static>> {
    let (cert_chain, key) = crate::tls::load_or_generate_cert(cert_path, key_path)?;
    let mut server_config =
        ServerConfig::with_single_cert(cert_chain, key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

/// Returns default server configuration along with its certificate.
fn configure_self_signed_server() -> Result<ServerConfig, Box<dyn Error + Send + Sync + 'static>> {
    let (cert_chain, key) = crate::tls::generate_self_signed_pair()?;

    let mut server_config =
        ServerConfig::with_single_cert(cert_chain, key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok(server_config)
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
