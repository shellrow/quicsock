//! TLS module for managing certificates and private keys.

pub mod certificate;
pub mod key;

use std::path::Path;
use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a self-signed certificate and private key
pub fn generate_self_signed_pair() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let cert_chain = vec![CertificateDer::from(cert.cert)];
    Ok((cert_chain, key))
}

/// Load or generate certificate and private key
pub fn load_or_generate_cert(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        let cert_chain = certificate::load_certs(cert_path)?;
        let key = key::load_key(key_path)?;
        Ok((cert_chain, key))
    } else {
        generate_self_signed_pair()
    }
}
