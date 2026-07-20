//! `-p host:container`: publishing a port should make the container
//! reachable from the host, through the TCP relay `spawn_port_forwarder`
//! sets up (the iptables DNAT approach this replaced didn't survive
//! locally-originated loopback connections - see its removal in the
//! project history for why this is a plain relay instead).
//!
//! Needs outbound network access to pull `busybox:latest`; skips (rather
//! than failing the suite) if Docker Hub isn't reachable, matching
//! `kiln-image/tests/registry_pull.rs`.

use kiln_cli::commands::{network, run};
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container/network requires root in this environment");
        return false;
    }
    true
}

#[test]
fn published_port_is_reachable_from_the_host() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    network::run(&store, network::Command::Create { name: "portstest".to_string(), subnet: "172.29.0.0/24".to_string() })
        .expect("create network");

    let mut spec = run::RunSpec::new("busybox:latest");
    spec.command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "mkdir -p /www && echo published-port-works > /www/index.html && httpd -f -p 8080 -h /www".to_string(),
    ];
    spec.network = Some("portstest".to_string());
    spec.ports = vec!["18099:8080".to_string()];

    let container = run::start(&store, spec, None).expect("start");

    // The relay's host-side `TcpListener` accepts immediately once the
    // container is attached to the network, but forwarding only succeeds
    // once busybox's `httpd` has actually started listening inside the
    // container - so a `connect()` succeeding isn't enough on its own;
    // retry the whole request/response until the body is non-empty, not
    // just the initial connect. Reading is bounded by a read timeout
    // rather than `read_to_string`'s wait-for-EOF: busybox's `httpd`
    // doesn't necessarily close the connection after one response even
    // for an HTTP/1.0 request, so waiting for EOF can hang indefinitely -
    // a bounded read of whatever's arrived within the timeout is enough
    // to see the body.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut body = String::new();
    let mut connected = false;
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect("127.0.0.1:18099") {
            connected = true;
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let _ = stream.write_all(b"GET /index.html HTTP/1.0\r\n\r\n");
            let mut buf = [0u8; 4096];
            body.clear();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => body.push_str(&String::from_utf8_lossy(&buf[..n])),
                    Err(_) => break,
                }
            }
            if body.contains("published-port-works") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);
    let _ = network::run(&store, network::Command::Rm { name: "portstest".to_string() });

    assert!(connected, "should have been able to connect to 127.0.0.1:18099 through the published port");
    assert!(body.contains("published-port-works"), "unexpected response body: {body:?}");
}
