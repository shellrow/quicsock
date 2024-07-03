[crates-badge]: https://img.shields.io/crates/v/quicsock.svg
[crates-url]: https://crates.io/crates/quicsock
[license-badge]: https://img.shields.io/crates/l/quicsock.svg
[examples-url]: https://github.com/shellrow/quicsock/tree/main/examples
[doc-url]: https://docs.rs/quicsock/latest/quicsock
[quicsock-github-url]: https://github.com/shellrow/quicsock

# quicsock
`quicsock` is a high-level and high-performance data transfer library, built on top of the `quinn` library.  
It allows for secure and efficient data transfers, with support for both self-signed and specified TLS certificates.  

Note: This project is currently under development and may breaking changes.

## Features
- High-speed data transfer using QUIC protocol
- Secure communication: Connections are encrypted using TLS
- Flexible certificate management: Use specified certificates or generate self-signed certificates
- Support for large file transfer

## Usage
Add `quicsock` to your dependencies  
```toml:Cargo.toml
[dependencies]
quicsock = "0.3"
```

For more details, see [examples][examples-url] or [doc][doc-url].  
