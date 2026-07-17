use crate::conn::Conn;
use crate::http::Request;
use kiln_image::store::Store;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

/// Loopback-only by design: this is a local dev/dashboard API, not a
/// service meant to be reachable from other machines. Binding
/// `127.0.0.1` (never `0.0.0.0`) keeps it off the network entirely -
/// WSL2's automatic `localhost` port forwarding to Windows still applies
/// to loopback addresses, so this is exactly as reachable from a native
/// Windows Electron process as it needs to be, and no more.
pub const TCP_PORT: u16 = 7867;

pub fn run(store: Store, socket_path: &Path) -> io::Result<()> {
    // A stale socket file from a kilnd that didn't shut down cleanly
    // (killed, crashed) would otherwise make bind() fail with "address in
    // use" even though nothing is actually listening; remove it first; a
    // *live* kilnd already holding the path would still fail bind() as
    // expected (its own listener owns the inode's actual bound state).
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let unix_listener = UnixListener::bind(socket_path)?;
    eprintln!("kilnd: listening on {} (unix)", socket_path.display());

    let tcp_listener = TcpListener::bind(("127.0.0.1", TCP_PORT))?;
    eprintln!("kilnd: listening on 127.0.0.1:{TCP_PORT} (tcp, loopback only)");

    let store = Arc::new(store);

    {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            for incoming in tcp_listener.incoming() {
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("kilnd: tcp accept: {e}");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                spawn_handler(Arc::clone(&store), Conn::Tcp(stream));
            }
        });
    }

    for incoming in unix_listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("kilnd: unix accept: {e}");
                continue;
            }
        };
        spawn_handler(Arc::clone(&store), Conn::Unix(stream));
    }
    Ok(())
}

fn spawn_handler(store: Arc<Store>, conn: Conn) {
    std::thread::spawn(move || {
        if let Err(e) = handle_connection(&store, conn) {
            if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) {
                eprintln!("kilnd: connection error: {e}");
            }
        }
    });
}

fn handle_connection(store: &Store, mut conn: Conn) -> io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let Some(req) = Request::read_from(&mut reader)? else {
        return Ok(());
    };
    crate::handlers::route(store, &req, &mut conn, &mut reader)
}
