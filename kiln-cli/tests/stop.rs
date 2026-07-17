//! `stop_container` must actually stop a container whose command ignores
//! `SIGTERM` - which is the common case, not an edge case: a container's
//! command runs as PID 1 of its own PID namespace, and per
//! `pid_namespaces(7)` that silently discards `SIGTERM` (and any other
//! default-terminate signal) unless it installed a handler for that exact
//! signal. This test doesn't bother with real namespace isolation (stop's
//! own logic doesn't care), just a real process that behaves the same way
//! that matters here: `trap '' TERM` makes plain `sh` ignore `SIGTERM`
//! exactly like an un-namespaced PID 1 would.

use kiln_cli::commands::stop::stop_container;
use kiln_cli::container::{now_unix, Container, Status};
use kiln_image::store::{Hash, Store};
use nix::sys::signal::Signal;
use nix::unistd::Uid;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: writing to /sys/fs/cgroup requires root in this environment");
        return false;
    }
    true
}

#[test]
fn stop_falls_back_to_sigkill_when_sigterm_is_ignored() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let id = format!("stoptest-{}", std::process::id());

    let mut child = Command::new("sh")
        .args(["-c", "trap '' TERM; sleep 30"])
        .spawn()
        .expect("spawn a SIGTERM-ignoring child");
    let pid = child.id() as i32;

    let cgroup = kiln_cli::cgroup::create_for(&id, &Default::default()).expect("create cgroup");
    cgroup.add_process(nix::unistd::Pid::from_raw(pid)).expect("add_process");

    let container = Container {
        id: id.clone(),
        name: id.clone(),
        image_reference: "scratch".to_string(),
        image_id: Hash::of_bytes(b"test"),
        command: vec!["sh".to_string()],
        pid: Some(pid),
        status: Status::Running,
        created_at: now_unix(),
        ip: None,
        network: None,
        volumes: Vec::new(),
        env: Vec::new(),
        memory_limit_bytes: None,
        cpu_limit: None,
        ports: Vec::new(),
        restart_policy: kiln_cli::container::RestartPolicy::No,
    };
    container.save(&store).expect("save container state");

    stop_container(&store, &id).expect("stop_container");

    // The definitive check: reap the child ourselves and confirm *how* it
    // died. Checking liveness via `kill(pid, 0)` instead would be
    // misleading here - a SIGKILLed-but-not-yet-reaped child is a zombie,
    // and `kill()` still succeeds against a zombie's still-valid pid, so
    // that check can't actually distinguish "really dead" from "not yet
    // reaped". The exit status can: it's SIGKILL only if the fallback
    // fired, since the child itself traps and discards SIGTERM.
    let status = child.wait().expect("reap the child");
    assert_eq!(
        status.signal(),
        Some(Signal::SIGKILL as i32),
        "the child must have been terminated by the SIGKILL fallback, not left running after an ignored SIGTERM"
    );

    let _ = cgroup.remove();
}
