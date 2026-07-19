//! Thread-per-connection TCP server, structurally identical to
//! `kilnd/src/server.rs` (which is exactly why `kilnd-core::{http,conn}`
//! exist - so this crate doesn't have to depend on `kilnd` or duplicate
//! its request-parsing loop just to reuse it).
//!
//! Binds `0.0.0.0`, not `127.0.0.1` - the one deliberate difference from
//! `kilnd`'s own server, whose loopback-only bind is explicitly
//! documented there as "not a service meant to be reachable from other
//! machines". This one is exactly that: a service other machines are
//! meant to reach.

use crate::auth::TokenStore;
use crate::store::RegistryStore;
use kilnd_core::conn::Conn;
use kilnd_core::http::Request;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::sync::Arc;

pub fn run(store: RegistryStore, port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    eprintln!("kiln-registry: listening on 0.0.0.0:{port}");

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
        std::thread::spawn(move || {
            let mut conn = Conn::Tcp(stream);
            if let Err(e) = handle_connection(&store, &tokens, &mut conn) {
                if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) {
                    eprintln!("kiln-registry: connection error: {e}");
                }
            }
        });
    }
    Ok(())
}

fn handle_connection(store: &RegistryStore, tokens: &TokenStore, conn: &mut Conn) -> io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let Some(req) = Request::read_from(&mut reader)? else {
        return Ok(());
    };
    crate::handlers::route(store, tokens, &req, conn)
}
