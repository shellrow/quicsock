//! Private key handling utilities

use std::{fs, path::Path};
use anyhow::{Context, Result};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// Load private key from a file
pub fn load_key(key_path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .context("malformed PKCS #1 private key")?
            .ok_or_else(|| anyhow::Error::msg("no private keys found"))?
    };
    Ok(key)
}
