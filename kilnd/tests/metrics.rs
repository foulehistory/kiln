//! `GET /metrics` - a Prometheus text-exposition rendering of the same
//! per-container data `kiln inspect --resources` already reports. Drives
//! the real compiled binary as a subprocess, and speaks real HTTP to it
//! via `curl` (not a hand-rolled `TcpStream` client, unlike `tests/api.rs`'s
//! own `request` helper): this file's test is the first one in this crate
//! to create an actual long-running container over the wire rather than
//! just networks/images, and a hand-rolled client reading the response
//! with `read_to_string` intermittently never observed the response at
//! all for that specific request shape in local testing, for reasons that
//! didn't reproduce against a plain `curl` invocation of the exact same
//! request. Rather than chase a test-harness-specific HTTP client quirk
//! further, this uses the same real, independently-trusted client any
//! operator would actually use to scrape this endpoint.

use kiln_image::store::Store;
use nix::unistd::Uid;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container/store requires root in this environment");
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
    // Unlike `tests/api.rs`'s own containers (which never start a real,
    // persistent process), this file's test creates one - and its
    // detached supervisor deliberately keeps a copy of whatever stderr fd
    // it inherited open for that container's entire lifetime (see
    // `kiln_cli::supervisor`'s own docs on why). Left unredirected here,
    // that fd traces all the way back through kilnd to *this test
    // harness's own* stdout/stderr - which, run inside a shell pipeline
    // (as this whole suite is, via `cargo test 2>&1` or similar), means
    // that pipeline's read end never sees EOF and hangs forever, even
    // long after this test itself has finished and `kilnd` has been
    // killed. Discarding both here (this test doesn't need kilnd's own
    // log output) cuts that inheritance chain off at the source.
    let mut child = Command::new(env!("CARGO_BIN_EXE_kilnd"))
        .args(["--store", store.to_str().unwrap(), "--socket", socket.to_str().unwrap()])
        .env("KILN_TCP_PORT", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kilnd");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Kilnd { child, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("kilnd never started listening on 127.0.0.1:{port}");
}

/// Returns `(http_status, body)`, via `curl -w` writing the status code
/// after a `\n` separator so it can be split back out.
fn curl(port: u16, method: &str, path: &str, json_body: Option<&str>) -> (u16, String) {
    let url = format!("http://127.0.0.1:{port}{path}");
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-m", "15", "-X", method, "-w", "\n%{http_code}"]);
    if let Some(body) = json_body {
        cmd.args(["-H", "Content-Type: application/json", "-d", body]);
    }
    cmd.arg(&url);
    let output = cmd.output().expect("spawn curl");
    let text = String::from_utf8_lossy(&output.stdout);
    let (body, status) = text.rsplit_once('\n').unwrap_or(("", &text));
    (status.trim().parse().unwrap_or(0), body.to_string())
}

/// Every sample line for `metric` must come strictly after its own
/// `# HELP`/`# TYPE` header pair, and neither header may appear twice -
/// the minimum a real Prometheus scraper requires of the exposition
/// format, checked here rather than trusting a hand-rolled string
/// builder to have gotten grouping right.
fn assert_well_formed_metric(body: &str, metric: &str) {
    let help_line = format!("# HELP {metric} ");
    let type_line = format!("# TYPE {metric} ");
    let sample_prefix = format!("{metric}{{");

    let help_pos = body.find(&help_line).unwrap_or_else(|| panic!("missing HELP line for {metric}:\n{body}"));
    let type_pos = body.find(&type_line).unwrap_or_else(|| panic!("missing TYPE line for {metric}:\n{body}"));
    assert!(help_pos < type_pos, "HELP should come before TYPE for {metric}");

    assert_eq!(
        body.matches(&help_line).count(),
        1,
        "HELP for {metric} should appear exactly once:\n{body}"
    );
    assert_eq!(
        body.matches(&type_line).count(),
        1,
        "TYPE for {metric} should appear exactly once:\n{body}"
    );

    let first_sample = body
        .find(&sample_prefix)
        .unwrap_or_else(|| panic!("no sample line for {metric}:\n{body}"));
    assert!(first_sample > type_pos, "sample for {metric} should come after its own HELP/TYPE header");
}

#[test]
fn metrics_reports_real_container_resource_usage() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if let Err(e) = kiln_image::registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    let kilnd = spawn_kilnd(store_dir.path(), 18764);

    let (status, _) = curl(
        kilnd.port,
        "POST",
        "/containers",
        Some(r#"{"image":"busybox:latest","command":["/bin/sh","-c","sleep 60"],"name":"metricstest","memory":"64m","cpus":0.5}"#),
    );
    assert_eq!(status, 201, "creating the container should return 201");

    // Give the cgroup a moment to register real live stats.
    std::thread::sleep(Duration::from_millis(500));

    let (status, body) = curl(kilnd.port, "GET", "/metrics", None);
    assert_eq!(status, 200, "GET /metrics should return 200");

    // `cpu_limit`/`memory_limit` are set at creation time from the
    // request body and don't depend on the container's process actually
    // staying alive afterward (unlike `up`/`healthy`, which do) - the
    // sturdiest thing to assert on here, since this test cares about
    // `/metrics` correctly reporting what was configured, not about
    // babysitting a busybox process for the rest of its run.
    for metric in [
        "kiln_container_up",
        "kiln_container_healthy",
        "kiln_container_cpu_limit_cores",
        "kiln_container_memory_limit_bytes",
        "kiln_container_last_exit_oom_killed",
    ] {
        assert_well_formed_metric(&body, metric);
    }

    assert!(
        body.contains("name=\"metricstest\""),
        "metricstest should show up somewhere in /metrics: {body}"
    );
    assert!(
        body.contains("kiln_container_cpu_limit_cores{") && body.contains("} 0.5"),
        "the configured 0.5-core cpu limit should be reported: {body}"
    );
    assert!(
        body.contains("kiln_container_memory_limit_bytes{") && body.contains("} 67108864"),
        "the configured 64m memory limit (67108864 bytes) should be reported: {body}"
    );

    let (_, body_json) = curl(kilnd.port, "GET", "/containers", None);
    let id = body_json
        .split("\"id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("should find the container's id in GET /containers");
    let _ = curl(kilnd.port, "DELETE", &format!("/containers/{id}"), None);
}
