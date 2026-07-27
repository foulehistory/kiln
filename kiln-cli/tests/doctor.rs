//! Real reproduction of the other bug found live in the same incident as
//! `network_hosts_refresh.rs`'s: a `start` attempt interrupted before the
//! container's process either exited on its own or went through `stop`'s
//! own reaping leaves it registered in `cgroup.procs` with nothing left
//! to clean it up - the next `start`/`restart` under the same container
//! id then hit a raw `EBUSY` trying to `rmdir` that leftover cgroup
//! directory (cgroupfs refuses `rmdir` on a cgroup with live members,
//! even though it has no subdirectories of its own).
//!
//! Rather than literally killing `kiln`/`kilnd` mid-launch (non-
//! deterministic to orchestrate in a test), this reproduces the exact
//! end state that matters: a real, still-alive process registered as a
//! cgroup member while the container's own persisted state says it
//! isn't running - which is precisely what an interrupted start leaves
//! behind, and precisely what `CgroupV2::create`'s self-heal (and `kiln
//! doctor`) has to detect and clean up.

use kiln_cli::commands::{network, run};
use kiln_cli::container::{Container, Status};
use kiln_image::registry;
use kiln_image::store::Store;
use kilnd_core::cgroups::CgroupV2;
use nix::sys::signal::kill;
use nix::unistd::{Pid, Uid};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container/cgroup requires root in this environment");
        return false;
    }
    true
}

/// Starts a real, long-lived busybox container under `name`, then
/// simulates an interrupted start by marking it `Exited` in the store
/// *without* touching its still-very-alive real process - exactly what a
/// supervisor that got killed before it could record a real exit (or
/// before `stop`'s own reaping ran) would leave behind: state says not
/// running, but the process (and its cgroup membership) is still there.
fn start_then_simulate_orphan(store: &Store, network_name: &str, name: &str) -> (Container, i32) {
    let mut spec = run::RunSpec::new("busybox:latest");
    spec.name = Some(name.to_string());
    spec.command = vec!["/bin/sh".to_string(), "-c".to_string(), "sleep 300".to_string()];
    spec.network = Some(network_name.to_string());
    let container = run::start(store, spec, None).expect("start");
    let pid = container.pid.expect("started container should have a pid");

    let mut orphaned = container.clone();
    orphaned.status = Status::Exited(-1);
    orphaned.save(store).expect("save simulated-exited state");

    (orphaned, pid)
}

fn is_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn interrupted_start_orphan_is_reaped_automatically_on_restart() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    network::run(
        &store,
        network::Command::Create {
            name: "doctortest1".to_string(),
            subnet: "172.32.0.0/24".to_string(),
        },
    )
    .expect("create network");

    let (_orphaned, pid) = start_then_simulate_orphan(&store, "doctortest1", "orphan-restart");
    assert!(is_alive(pid), "sanity check: the orphaned process should still be alive");

    // Before the fix, this would fail with a raw EBUSY trying to rmdir
    // the still-occupied cgroup left by the "interrupted" start above.
    let restarted = run::restart(&store, "orphan-restart").expect("restart should self-heal past the orphaned cgroup, not fail with EBUSY");

    assert!(!is_alive(pid), "the orphaned process should have been killed by the self-heal");
    assert_ne!(
        restarted.pid.unwrap(),
        pid,
        "the restarted container should be a genuinely new process, not the orphaned one"
    );

    let _ = kiln_cli::commands::stop::stop_container(&store, &restarted.id);
    kiln_cli::cgroup::remove(&restarted.id);
    let _ = network::run(
        &store,
        network::Command::Rm {
            name: "doctortest1".to_string(),
        },
    );
}

#[test]
fn kiln_doctor_finds_and_fixes_orphaned_cgroup_processes() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    network::run(
        &store,
        network::Command::Create {
            name: "doctortest2".to_string(),
            subnet: "172.33.0.0/24".to_string(),
        },
    )
    .expect("create network");

    let (orphaned, pid) = start_then_simulate_orphan(&store, "doctortest2", "orphan-doctor");
    assert!(is_alive(pid), "sanity check: the orphaned process should still be alive");

    // `doctor` ignores anything younger than `MIN_AGE_BEFORE_FLAGGING` (a
    // real-world race guard against sweeping up a container that's still
    // legitimately mid-start elsewhere) - outlast it so this orphan is old
    // enough to actually get flagged.
    std::thread::sleep(std::time::Duration::from_secs(4));

    // Report-only pass: must find it, must not touch it.
    kiln_cli::commands::doctor::run(&store, kiln_cli::commands::doctor::Args { fix: false }).expect("doctor (report only)");
    assert!(is_alive(pid), "a report-only `kiln doctor` pass must not kill anything");

    // --fix pass: must actually clean it up.
    kiln_cli::commands::doctor::run(&store, kiln_cli::commands::doctor::Args { fix: true }).expect("doctor --fix");
    assert!(!is_alive(pid), "`kiln doctor --fix` should have killed the orphaned process");

    let cgroup_dir = kiln_cli::cgroup::open(&orphaned.id);
    if let Some(dir) = cgroup_dir {
        let remaining = CgroupV2::from_existing(dir).processes().unwrap_or_default();
        assert!(remaining.is_empty(), "the cgroup should have no member processes left after --fix");
    }

    kiln_cli::cgroup::remove(&orphaned.id);
    let _ = network::run(
        &store,
        network::Command::Rm {
            name: "doctortest2".to_string(),
        },
    );
}
