//! End-to-end proof that `kiln run`'s own code path - not just the
//! `spawn_isolated` primitive in isolation (see
//! `kilnd-core/tests/namespace_isolation.rs`) - actually remaps a real
//! container's identity: a process that looks like `uid 0` from inside
//! must be a genuinely unprivileged, dedicated uid from the host's own
//! point of view, in Kiln's real fixed subordinate range
//! (`kiln_image::identity::SUBORDINATE_UID_BASE`), never literal root.
//!
//! `kilnd-core`'s test constructs its own `IdMap` by hand; this one goes
//! through `kiln_cli::commands::run::start` exactly as the `kiln run` CLI
//! does, so it would actually catch `run.rs` ever drifting away from
//! `identity::container_id_map` (e.g. a refactor that forgets to wire it
//! up) - a class of regression the lower-level test can't see.

use kiln_cli::commands::run::{start, RunSpec};
use kiln_image::identity::{SUBORDINATE_GID_BASE, SUBORDINATE_RANGE, SUBORDINATE_UID_BASE};
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real cgroup/container requires root in this environment");
        return false;
    }
    true
}

/// Parses `/proc/<pid>/status`'s `Uid:`/`Gid:` line - four
/// tab-separated numbers (real, effective, saved, filesystem); the real
/// one (index 0) is what the kernel actually enforces against, so it's
/// the one that matters for "is this genuinely unprivileged on the host".
fn real_id_from_status(pid: i32, field: &str) -> u32 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read /proc/<pid>/status");
    let line = status.lines().find(|l| l.starts_with(field)).unwrap_or_else(|| panic!("no {field} line"));
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn kiln_run_remaps_a_real_container_to_the_subordinate_id_range() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    // A real, runnable rootfs is needed - unlike the cgroup/restart-policy
    // tests, this one has to inspect a *live* process, so `scratch` (no
    // binaries, exec fails almost instantly) won't do.
    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    let mut spec = RunSpec::new("busybox:latest");
    spec.command = vec!["sleep".to_string(), "30".to_string()];
    let container = start(&store, spec, None).expect("start");
    let pid = container.pid.expect("Running implies pid");

    let host_uid = real_id_from_status(pid, "Uid:");
    let host_gid = real_id_from_status(pid, "Gid:");

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);

    // The actual security property: the host kernel enforces permissions
    // against this id, and it must be a dedicated, unprivileged one -
    // never uid/gid 0, which would mean the container process is real
    // root on the host despite looking like root to itself.
    assert_ne!(host_uid, 0, "container process must never be real root on the host");
    assert_ne!(host_gid, 0, "container process must never be real root on the host");
    assert!(
        (SUBORDINATE_UID_BASE..SUBORDINATE_UID_BASE + SUBORDINATE_RANGE).contains(&host_uid),
        "host uid {host_uid} should fall in Kiln's own subordinate range {SUBORDINATE_UID_BASE}..{}",
        SUBORDINATE_UID_BASE + SUBORDINATE_RANGE
    );
    assert!(
        (SUBORDINATE_GID_BASE..SUBORDINATE_GID_BASE + SUBORDINATE_RANGE).contains(&host_gid),
        "host gid {host_gid} should fall in Kiln's own subordinate range {SUBORDINATE_GID_BASE}..{}",
        SUBORDINATE_GID_BASE + SUBORDINATE_RANGE
    );
}
