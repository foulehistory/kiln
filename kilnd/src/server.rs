use kilnd_core::conn::Conn;
use kilnd_core::http::{Request, Response};
use kiln_image::store::Store;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

/// Loopback-only by default: this is a local dev/dashboard API, not a
/// service meant to be reachable from other machines. Binding
/// `127.0.0.1` (never `0.0.0.0`) keeps it off the network entirely -
/// WSL2's automatic `localhost` port forwarding to Windows still applies
/// to loopback addresses, so this is exactly as reachable from a native
/// Windows Electron process as it needs to be, and no more.
///
/// [`remote_config`] below is the one deliberate, opt-in exception -
/// `kiln node`'s multi-host support needs *some* kilnd reachable from
/// another machine, since that's the only way a `kiln-compose up`
/// service tagged `node: <name>` actually gets created on that node.
/// Everything on this default listener is completely unaffected by
/// whether that's enabled: no token, no new port, no behavior change.
pub const DEFAULT_TCP_PORT: u16 = 7867;

/// `KILN_TCP_PORT` if set (kiln-dashboard's `electron/main.js` already
/// reads this same variable to decide which port to *connect* to), else
/// [`DEFAULT_TCP_PORT`] - lets more than one `kilnd` run side by side
/// (e.g. an isolated instance under test) without colliding on the
/// well-known port.
fn tcp_port() -> u16 {
    std::env::var("KILN_TCP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_TCP_PORT)
}

/// A second, separate TCP listener - bound `0.0.0.0`, unlike the default
/// one above - that only exists at all if `KILN_REMOTE_TOKEN` is set.
/// Every request on it must carry `Authorization: Bearer <token>` or get
/// a 401 before ever reaching a handler (see `route`'s caller in this
/// file). A deliberately separate port (not a second bind on the same
/// port as the default listener, which the kernel wouldn't even allow)
/// so the two trust boundaries can never be confused with each other at
/// the socket level, not just at the auth-check level.
struct RemoteConfig {
    token: String,
    port: u16,
}

const DEFAULT_REMOTE_PORT: u16 = 7868;

fn remote_config() -> Option<RemoteConfig> {
    let token = std::env::var("KILN_REMOTE_TOKEN").ok().filter(|t| !t.is_empty())?;
    let port = std::env::var("KILN_REMOTE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_REMOTE_PORT);
    Some(RemoteConfig { token, port })
}

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

    let port = tcp_port();
    let tcp_listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("kilnd: listening on 127.0.0.1:{port} (tcp, loopback only)");

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
                spawn_handler(Arc::clone(&store), Conn::Tcp(stream), None);
            }
        });
    }

    if let Some(remote) = remote_config() {
        let remote_listener = TcpListener::bind(("0.0.0.0", remote.port))?;
        eprintln!("kilnd: listening on 0.0.0.0:{} (tcp, remote - bearer token required)", remote.port);
        let token = Arc::new(remote.token);
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            for incoming in remote_listener.incoming() {
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("kilnd: remote tcp accept: {e}");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                spawn_handler(Arc::clone(&store), Conn::Tcp(stream), Some(Arc::clone(&token)));
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
        spawn_handler(Arc::clone(&store), Conn::Unix(stream), None);
    }
    Ok(())
}

/// `expected_token: None` means this connection came from a trusted
/// listener (the default loopback TCP port, or the Unix socket) and is
/// dispatched exactly as before; `Some(token)` means it came from the
/// remote listener and every request on it must present that token.
fn spawn_handler(store: Arc<Store>, conn: Conn, expected_token: Option<Arc<String>>) {
    std::thread::spawn(move || {
        if let Err(e) = handle_connection(&store, conn, expected_token.as_ref().map(|t| t.as_str())) {
            if !matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) {
                eprintln!("kilnd: connection error: {e}");
            }
        }
    });
}

fn handle_connection(store: &Store, mut conn: Conn, expected_token: Option<&str>) -> io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let Some(req) = Request::read_from(&mut reader)? else {
        return Ok(());
    };
    if let Some(expected) = expected_token {
        if req.bearer_token() != Some(expected) {
            return Response::text(401, "missing or invalid bearer token").write_to(&mut conn);
        }
    }
    crate::handlers::route(store, &req, &mut conn, &mut reader)
}
