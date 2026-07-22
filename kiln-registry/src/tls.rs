//! Opt-in native TLS for `kiln-registry`'s own listener - see
//! `server.rs`'s own docs on why this is a small, self-contained type
//! local to this crate rather than a new variant on `kilnd_core::conn::Conn`
//! (shared with `kilnd`, which has no need for TLS at all).

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

/// Loads a PEM certificate chain + private key into a reusable
/// `rustls::ServerConfig` - parsed once at startup, not per connection.
pub fn load_server_config(cert_path: &Path, key_path: &Path) -> io::Result<Arc<rustls::ServerConfig>> {
    let cert_file = File::open(cert_path).map_err(|e| io::Error::new(e.kind(), format!("reading TLS cert {}: {e}", cert_path.display())))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parsing TLS cert {}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", cert_path.display()),
        ));
    }

    let key_file = File::open(key_path).map_err(|e| io::Error::new(e.kind(), format!("reading TLS key {}: {e}", key_path.display())))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parsing TLS key {}: {e}", key_path.display())))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("no private key found in {}", key_path.display())))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("building TLS config: {e}")))?;
    Ok(Arc::new(config))
}

/// A connection that's either plain TCP or TLS-wrapped TCP - the one
/// place this crate's request-handling code needs to know the
/// difference, everywhere else just sees `Read`/`Write`. Deliberately
/// not `Clone`/no `try_clone`-style split: `server.rs`'s own
/// `handle_connection` reads the request through a `BufReader::new(&mut
/// stream)` borrow (see `kilnd_core::http::Request::read_from`'s own
/// docs on why that pattern needs no such split) and reuses the same
/// value to write the response once that borrow ends.
pub enum RegistryStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl RegistryStream {
    pub fn plain(stream: TcpStream) -> Self {
        RegistryStream::Plain(stream)
    }

    /// The TLS handshake itself happens lazily, on the first real
    /// read/write through the returned `StreamOwned` - not here.
    pub fn tls(config: Arc<rustls::ServerConfig>, stream: TcpStream) -> io::Result<Self> {
        let conn = rustls::ServerConnection::new(config).map_err(|e| io::Error::other(format!("starting TLS handshake: {e}")))?;
        Ok(RegistryStream::Tls(Box::new(rustls::StreamOwned::new(conn, stream))))
    }
}

impl Read for RegistryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RegistryStream::Plain(s) => s.read(buf),
            RegistryStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for RegistryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            RegistryStream::Plain(s) => s.write(buf),
            RegistryStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            RegistryStream::Plain(s) => s.flush(),
            RegistryStream::Tls(s) => s.flush(),
        }
    }
}
