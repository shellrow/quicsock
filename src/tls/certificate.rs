//! Certificate handling utilities

use std::{fs, io, path::Path};
use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;

/// Get the native certificates from the system. return rustls::RootCertStore
pub fn get_native_certs() -> io::Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                match root_store.add(cert) {
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            Ok(root_store)
        }
        Err(e) => return Err(e),
    }
}

/// Load certificate chain from a file
pub fn load_certs(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        vec![CertificateDer::from(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain)
            .collect::<Result<Vec<_>, _>>()
            .context("invalid PEM-encoded certificate")?
    };
    Ok(cert_chain)
}
