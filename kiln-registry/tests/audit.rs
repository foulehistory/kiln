//! Real end-to-end proof that `kiln-registry`'s audit log actually
//! records what it claims to: a push and a pull by two different real
//! accounts, plus a deliberate RBAC refusal (a pull-role account trying
//! to push), all show up correctly via `kiln-registry audit` - never the
//! credentials themselves, only the account each request resolved to.
//! Drives the real compiled binary end-to-end over HTTP, same style as
//! `tests/rbac.rs`/`tests/tag_and_push.rs`.

use kiln_image::build;
use kiln_image::image::tag_reference;
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: building/materializing requires root in this environment");
        return false;
    }
    true
}

struct Registry {
    child: Child,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_registry(data_dir: &Path, port: u16) -> Registry {
    let child = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.to_str().unwrap(), "serve", "--port", &port.to_string()])
        .spawn()
        .expect("spawn kiln-registry");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Registry { child };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("kiln-registry never started listening on 127.0.0.1:{port}");
}

fn add_user(data_dir: &Path, username: &str, password: &str, role: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "user",
            "add",
            username,
            password,
            "--role",
            role,
        ])
        .status()
        .expect("run kiln-registry user add");
    assert!(status.success());
}

fn run_audit(data_dir: &Path, extra_args: &[&str]) -> String {
    let mut args = vec!["--data-dir", data_dir.to_str().unwrap(), "audit"];
    args.extend_from_slice(extra_args);
    let output = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(&args)
        .output()
        .expect("run kiln-registry audit");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn audit_records_a_push_a_pull_and_a_deliberate_rbac_refusal() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let ctx = tempfile::tempdir().unwrap();
    std::fs::write(ctx.path().join("hello.txt"), "hello from audit test\n").unwrap();
    let output = build::build(&store, ctx.path(), "FROM scratch\nCOPY hello.txt /hello.txt\n").expect("build");

    let registry_dir = tempfile::tempdir().unwrap();
    let port = 15900 + (std::process::id() % 500) as u16;
    add_user(registry_dir.path(), "alice", "alicepass", "push");
    add_user(registry_dir.path(), "bob", "bobpass", "pull");
    let _registry = spawn_registry(registry_dir.path(), port);

    let target = format!("127.0.0.1:{port}/alice/hello:latest");
    tag_reference(&store, &output.image_id, &target).expect("tag under alice's namespace");

    // alice (push role) pushes to her own namespace - allowed.
    std::env::set_var("KILN_REGISTRY_USER", "alice");
    std::env::set_var("KILN_REGISTRY_PASS", "alicepass");
    registry::push(&store, &output.image_id, &target).expect("alice can push to her own namespace");

    // bob (pull role) pulls it back - allowed.
    std::env::set_var("KILN_REGISTRY_USER", "bob");
    std::env::set_var("KILN_REGISTRY_PASS", "bobpass");
    let pull_store_dir = tempfile::tempdir().unwrap();
    let pull_store = Store::open(pull_store_dir.path()).unwrap();
    registry::pull(&pull_store, &target, true).expect("bob can pull");

    // bob (pull role) tries to push to alice's namespace - a deliberate
    // RBAC refusal, gated at /token itself (a pull-role account can never
    // obtain a push token for anything, its own namespace or not).
    let forbidden_target = format!("127.0.0.1:{port}/alice/hello2:latest");
    tag_reference(&store, &output.image_id, &forbidden_target).expect("tag a second reference for the refused push");
    registry::push(&store, &output.image_id, &forbidden_target).expect_err("bob must not be able to push at all, pull-role");

    let full_log = run_audit(registry_dir.path(), &[]);
    assert!(
        full_log.contains("alice") && full_log.contains("push") && full_log.contains("allowed") && full_log.contains("alice/hello:latest"),
        "alice's push should be in the audit log: {full_log}"
    );
    assert!(
        full_log.contains("bob") && full_log.contains("pull") && full_log.contains("allowed") && full_log.contains("alice/hello:latest"),
        "bob's pull should be in the audit log: {full_log}"
    );
    assert!(
        full_log.contains("bob") && full_log.contains("push") && full_log.contains("denied") && full_log.contains("alice/hello2"),
        "bob's refused push should be in the audit log as denied: {full_log}"
    );

    // --user alice should only show alice's own entries.
    let alice_only = run_audit(registry_dir.path(), &["--user", "alice"]);
    assert!(
        alice_only.contains("alice"),
        "alice-filtered log should still contain alice: {alice_only}"
    );
    assert!(!alice_only.contains("bob"), "alice-filtered log should not contain bob: {alice_only}");

    // --denied-only should only show the refused push.
    let denied_only = run_audit(registry_dir.path(), &["--denied-only"]);
    assert!(
        denied_only.contains("denied"),
        "denied-only log should contain the refusal: {denied_only}"
    );
    assert!(
        !denied_only.contains("allowed"),
        "denied-only log should not contain any allowed entries: {denied_only}"
    );
}
