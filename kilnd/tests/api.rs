//! `kilnd` has no lib.rs (only `main.rs`), so its first tests drive the
//! real compiled binary as a subprocess and speak real HTTP to it - one
//! end-to-end test per new endpoint (`POST /networks`, `DELETE
//! /networks/:name`, `DELETE /images/:id`), matching how
//! `kiln-compose/tests/down.rs` already tests a bin-only crate.
//!
//! Each test gets its own `KILN_TCP_PORT` so tests can run concurrently
//! (the default for `cargo test`) without colliding on the port - and so
//! a leftover `kilnd` from manual testing, already bound to the default
//! 7867, can't block the suite either.

use kiln_image::store::Store;
use nix::unistd::Uid;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real network/store requires root in this environment");
        return false;
    }
    true
}

struct Kilnd {
    child: Child,
    port: u16,
}

impl Drop for Kilnd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_kilnd(store: &Path, port: u16) -> Kilnd {
    let socket = store.join("kilnd.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kilnd"))
        .args(["--store", store.to_str().unwrap(), "--socket", socket.to_str().unwrap()])
        .env("KILN_TCP_PORT", port.to_string())
        .spawn()
        .expect("spawn kilnd");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Kilnd { child, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Reap it ourselves before panicking - `Child`'s own `Drop` doesn't
    // wait() on the process, which would otherwise leave a zombie behind
    // once it eventually exits (this early-return path is the only one
    // that doesn't go through `Kilnd`'s own Drop impl, which already
    // handles this for every other path).
    let _ = child.kill();
    let _ = child.wait();
    panic!("kilnd never started listening on 127.0.0.1:{port}");
}

/// One request per connection, always `Connection: close` on the server
/// side (see `kilnd/src/http.rs`'s module docs) - so a blocking read to
/// EOF after writing the request is all a test client needs.
fn request(port: u16, method: &str, path: &str, json_body: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to kilnd");
    let body = json_body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
    stream.shutdown(std::net::Shutdown::Write).ok();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");

    let status: u16 = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, body)
}

#[test]
fn post_networks_creates_a_network() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let kilnd = spawn_kilnd(store_dir.path(), 18761);

    let (status, _) = request(kilnd.port, "POST", "/networks", Some(r#"{"name":"apitest-create"}"#));
    assert_eq!(status, 201, "creating a network should return 201");

    let (status, body) = request(kilnd.port, "GET", "/networks", None);
    assert_eq!(status, 200);
    assert!(body.contains("apitest-create"), "the new network should show up in GET /networks: {body}");

    let (_, _) = request(kilnd.port, "DELETE", "/networks/apitest-create", None);
}

#[test]
fn delete_networks_name_removes_a_network() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let kilnd = spawn_kilnd(store_dir.path(), 18762);

    let (status, _) = request(kilnd.port, "POST", "/networks", Some(r#"{"name":"apitest-remove"}"#));
    assert_eq!(status, 201);

    let (status, _) = request(kilnd.port, "DELETE", "/networks/apitest-remove", None);
    assert_eq!(status, 200, "removing an existing network should return 200");

    let (status, body) = request(kilnd.port, "GET", "/networks", None);
    assert_eq!(status, 200);
    assert!(
        !body.contains("apitest-remove"),
        "the removed network should be gone from GET /networks: {body}"
    );

    let (status, _) = request(kilnd.port, "DELETE", "/networks/no-such-network", None);
    assert_eq!(status, 404, "removing a network that doesn't exist should 404");
}

#[test]
fn delete_images_id_untags_and_deletes_the_image() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let ctx = tempfile::tempdir().unwrap();
    let output = kiln_image::build::build(&store, ctx.path(), "FROM scratch\n").expect("build a trivial scratch image");
    store.tag("apitest-image", "latest", output.image_id).expect("tag the built image");

    let kilnd = spawn_kilnd(store_dir.path(), 18763);

    let (status, body) = request(kilnd.port, "GET", "/images", None);
    assert_eq!(status, 200);
    assert!(
        body.contains("apitest-image"),
        "the tagged image should show up in GET /images first: {body}"
    );

    let (status, _) = request(kilnd.port, "DELETE", &format!("/images/{}", output.image_id), None);
    assert_eq!(status, 200, "removing an existing image should return 200");

    let (status, body) = request(kilnd.port, "GET", "/images", None);
    assert_eq!(status, 200);
    assert!(
        !body.contains("apitest-image"),
        "the removed image's tag should be gone from GET /images: {body}"
    );

    let (status, _) = request(kilnd.port, "DELETE", &format!("/images/{}", output.image_id), None);
    assert_eq!(status, 404, "removing an already-removed image should 404");
}
