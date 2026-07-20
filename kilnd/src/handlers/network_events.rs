//! `GET /containers/:id/network-events` with `Upgrade: kiln-net-events` -
//! a live stream of the container's observed network flows, one JSON
//! object per line. Same "not a real WebSocket, both ends are ours"
//! reasoning as `exec.rs` (see its own module docs) - the dashboard's
//! Electron main process speaks raw HTTP `Upgrade` natively.
//!
//! Server-to-client only, unlike `exec`'s bidirectional pty shuttle - the
//! client never sends anything back, so this is a single loop rather
//! than two threads pumping in opposite directions. Attaches a
//! `kilnd_core::netbpf::FlowObserver` for the connection's own lifetime;
//! disconnecting (closing the dashboard's view) drops it, which detaches
//! the underlying eBPF programs - see `netbpf`'s own docs on why that's
//! safe to leave to `Drop`/process-exit semantics.

use kiln_cli::container::Container;
use kiln_image::store::Store;
use kilnd_core::conn::Conn;
use kilnd_core::http::{Request, Response};
use kilnd_core::netbpf::FlowObserver;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct FlowEventJson {
    to_container: bool,
    protocol: &'static str,
    src: String,
    dst: String,
    bytes: u16,
}

pub fn handle(store: &Store, id: &str, _req: &Request, stream: &mut Conn) -> io::Result<()> {
    let Some(container) = Container::resolve(store, id) else {
        return Response::text(404, "no such container").write_to(stream);
    };

    let mut observer = match FlowObserver::attach(&container.id) {
        Ok(o) => o,
        Err(e) => return Response::text(400, format!("{e}")).write_to(stream),
    };

    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: kiln-net-events\r\nConnection: Upgrade\r\n\r\n"
    )?;
    stream.flush()?;

    // A client that's gone stops accepting writes, which is the only
    // signal this direction-only stream has that it's time to stop -
    // `write_all`'s own `Err` on a closed socket ends the loop, dropping
    // `observer` and detaching the eBPF programs.
    loop {
        for event in observer.drain() {
            let json = FlowEventJson {
                to_container: event.to_container,
                protocol: if event.protocol == 6 { "tcp" } else { "udp" },
                src: format!("{}:{}", event.src_addr, event.src_port),
                dst: format!("{}:{}", event.dst_addr, event.dst_port),
                bytes: event.len,
            };
            let line = serde_json::to_string(&json).expect("FlowEventJson serialization cannot fail");
            stream.write_all(line.as_bytes())?;
            stream.write_all(b"\n")?;
        }
        stream.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}
