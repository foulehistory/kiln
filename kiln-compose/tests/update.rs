//! `kiln-compose update <service>`: replace one service's running
//! container without ever removing the old one until a new instance has
//! proven itself healthy - and roll back automatically (leaving the old
//! instance untouched) if it never does. Drives the real compiled binary
//! as a subprocess, same convention as `tests/down.rs` (`kiln-compose`
//! has no lib target).

use kiln_cli::container::Container;
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// A stand-in for `std::process::Output` that never blocks on pipe EOF.
///
/// `Command::output()`/`wait_with_output()` read stdout/stderr as *pipes*
/// and only return once every writer has closed them - but `kiln-compose
/// up`'s own detached, per-container supervisor deliberately keeps a
/// long-running service's stderr fd open for that container's entire
/// lifetime (see `kiln_cli::supervisor`'s own docs on why: so a setup
/// failure's error message isn't silently lost). For any service that
/// actually stays running - the realistic case `update` exists for -
/// that means the pipe's write end never closes, and `.output()` hangs
/// forever even though the `kiln-compose` process it was waiting on
/// already exited. Redirecting to real files instead sidesteps this
/// entirely: a file write never blocks on being read, so `.status()`
/// (which only waits on the direct child, not any pipe) returns as soon
/// as `kiln-compose` itself exits, regardless of what its detached
/// grandchildren are still doing.
struct CapturedOutput {
    success: bool,
    stderr: String,
}

/// `project` must be unique per test (not just per store): `pick_subnet`/
/// the bridge device name it derives are hashed from the project name
/// alone, and a Linux bridge is a host-global resource regardless of
/// which store two concurrently-running tests each use - two tests
/// sharing a project name race on creating (and later tearing down) the
/// exact same bridge device.
fn run_compose(store_dir: &Path, project_dir: &Path, project: &str, args: &[&str]) -> CapturedOutput {
    let stdout_file = tempfile::NamedTempFile::new().unwrap();
    let stderr_file = tempfile::NamedTempFile::new().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_kiln-compose"))
        .args(["--store", store_dir.to_str().unwrap(), "-f", "kiln.yaml", "-p", project])
        .args(args)
        .current_dir(project_dir)
        .stdout(stdout_file.reopen().unwrap())
        .stderr(stderr_file.reopen().unwrap())
        .status()
        .expect("spawn kiln-compose");
    CapturedOutput {
        success: status.success(),
        stderr: std::fs::read_to_string(stderr_file.path()).unwrap_or_default(),
    }
}

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container/network requires root in this environment");
        return false;
    }
    true
}

fn write_yaml(dir: &Path, web_command: &str) {
    std::fs::write(
        dir.join("kiln.yaml"),
        format!(
            r#"services:
  web:
    image: busybox:latest
    command: ["/bin/sh", "-c", {command:?}]
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O- http://127.0.0.1:8080/index.html | grep -q v"]
      interval: 1s
      timeout: 2s
      retries: 3
"#,
            command = web_command
        ),
    )
    .unwrap();
}

#[test]
fn update_promotes_a_new_instance_once_healthy() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    let project_dir = tempfile::tempdir().unwrap();
    write_yaml(
        project_dir.path(),
        "mkdir -p /www && echo v1 > /www/index.html && httpd -f -p 8080 -h /www",
    );

    let up = run_compose(store_dir.path(), project_dir.path(), "updatetest1", &["up", "-d"]);
    assert!(up.success, "up failed: {}", up.stderr);

    let before = Container::resolve(&store, "updatetest1_web").expect("web should be running after up");

    write_yaml(
        project_dir.path(),
        "mkdir -p /www && echo v2 > /www/index.html && httpd -f -p 8080 -h /www",
    );
    let update = run_compose(store_dir.path(), project_dir.path(), "updatetest1", &["update", "web", "--timeout", "20"]);
    assert!(update.success, "update failed: {}", update.stderr);

    let after = Container::resolve(&store, "updatetest1_web").expect("web should still resolve by its plain name after update");
    assert_ne!(
        after.id, before.id,
        "update should have promoted a genuinely new container, not reused the old one"
    );
    assert!(
        after.command.iter().any(|s| s.contains("v2")),
        "the promoted container should run the new command: {:?}",
        after.command
    );

    // The old container must be gone entirely, not just stopped.
    assert!(
        Container::load(&store, &before.id).is_none(),
        "the old instance should have been removed after a successful update"
    );

    // No leftover temp container from the promotion.
    assert!(
        Container::resolve(&store, "updatetest1_web__update").is_none(),
        "no temporary container should be left behind after a successful update"
    );

    let _ = run_compose(store_dir.path(), project_dir.path(), "updatetest1", &["down"]);
}

#[test]
fn update_rolls_back_when_the_new_instance_never_becomes_healthy() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    let project_dir = tempfile::tempdir().unwrap();
    write_yaml(
        project_dir.path(),
        "mkdir -p /www && echo v1 > /www/index.html && httpd -f -p 8080 -h /www",
    );

    let up = run_compose(store_dir.path(), project_dir.path(), "updatetest2", &["up", "-d"]);
    assert!(up.success, "up failed: {}", up.stderr);

    let before = Container::resolve(&store, "updatetest2_web").expect("web should be running after up");
    // Give the healthcheck a moment to actually report healthy before we
    // start relying on that being the pre-update baseline.
    std::thread::sleep(Duration::from_secs(2));

    // A command that never serves anything on 8080 - the healthcheck can
    // never pass.
    write_yaml(project_dir.path(), "exit 1");
    let update = run_compose(store_dir.path(), project_dir.path(), "updatetest2", &["update", "web", "--timeout", "8"]);
    assert!(!update.success, "update should fail when the new instance never becomes healthy");
    assert!(
        update.stderr.contains("update aborted"),
        "expected an 'update aborted' message, got: {:?}",
        update.stderr
    );

    let after = Container::resolve(&store, "updatetest2_web").expect("web should still resolve after a rolled-back update");
    assert_eq!(
        after.id, before.id,
        "the old instance should still be the one running after a rolled-back update"
    );
    let mut after = after;
    after.refresh(&store);
    assert_eq!(
        after.status,
        kiln_cli::container::Status::Running,
        "the old instance should still be running after rollback"
    );

    assert!(
        Container::resolve(&store, "updatetest2_web__update").is_none(),
        "the failed temp instance should have been cleaned up, not left behind"
    );

    let _ = run_compose(store_dir.path(), project_dir.path(), "updatetest2", &["down"]);
}
