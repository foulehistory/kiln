//! Thread-per-connection TCP server, structurally similar to
//! `kilnd/src/server.rs` (which is exactly why `kilnd-core::http` exists -
//! so this crate doesn't have to depend on `kilnd` or duplicate its
//! request-parsing logic just to reuse it). Unlike `kilnd`, this crate
//! defines its own connection type (`tls::RegistryStream`) rather than
//! using `kilnd_core::conn::Conn` - see `tls.rs`'s own docs on why.
//!
//! Binds `0.0.0.0`, not `127.0.0.1` - the one deliberate difference from
//! `kilnd`'s own server, whose loopback-only bind is explicitly
//! documented there as "not a service meant to be reachable from other
//! machines". This one is exactly that: a service other machines are
//! meant to reach.

use crate::auth::TokenStore;
use crate::store::RegistryStore;
use crate::tls::RegistryStream;
use kilnd_core::http::Request;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

/// `tls`, if given, is a `(cert, key)` PEM path pair - native TLS,
/// entirely opt-in (see `main.rs`'s own `Serve` flags). `None` (the
/// default) is plain HTTP, unchanged from before this existed.
pub fn run(store: RegistryStore, port: u16, tls: Option<(PathBuf, PathBuf)>) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let tls_config = match tls {
        Some((cert, key)) => {
            let config = crate::tls::load_server_config(&cert, &key)?;
            eprintln!("kiln-registry: listening on 0.0.0.0:{port} (tls)");
            Some(config)
        }
        None => {
            eprintln!("kiln-registry: listening on 0.0.0.0:{port}");
            None
        }
    };

    let store = Arc::new(store);
    let tokens = Arc::new(TokenStore::new());

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("kiln-registry: accept: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let store = Arc::clone(&store);
        let tokens = Arc::clone(&tokens);
        let tls_config = tls_config.clone();
        std::thread::spawn(move || {
            let mut conn = match tls_config {
                Some(config) => match RegistryStream::tls(config, stream) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("kiln-registry: TLS handshake setup: {e}");
                        return;
                    }
                },
                None => RegistryStream::plain(stream),
            };
            if let Err(e) = handle_connection(&store, &tokens, &mut conn) {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) {
                    eprintln!("kiln-registry: connection error: {e}");
                }
            }
        });
    }
    Ok(())
}

fn handle_connection(store: &RegistryStore, tokens: &TokenStore, conn: &mut RegistryStream) -> io::Result<()> {
    // A borrow, not a clone/split - `&mut RegistryStream` is itself
    // `Read`, so this needs no independent handle onto the connection
    // the way an owned `BufReader<RegistryStream>` would (which, for the
    // TLS variant, has no cheap equivalent anyway - see `tls.rs`'s own
    // docs). `reader` (and its borrow of `conn`) is dropped at the end of
    // this call, freeing `conn` up to write the response with right
    // after.
    let Some(req) = Request::read_from(&mut BufReader::new(&mut *conn))? else {
        return Ok(());
    };
    crate::handlers::route(store, tokens, &req, conn)
}
