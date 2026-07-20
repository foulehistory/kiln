//! End-to-end proof that a real container started via
//! `kiln_cli::commands::run::start` (the same path `kiln run` itself
//! uses) actually gets the restricted default profile
//! `kilnd_core::security` describes - not just that the module's own
//! logic is internally consistent, but that `run_container_init` wires
//! it in at all. Same "go through the real CLI path, inspect from the
//! host" style as `security_namespaces.rs`.

use kiln_cli::commands::run::{start, RunSpec};
use kiln_cli::container::Container;
use kiln_image::registry;
use kiln_image::store::Store;
use kilnd_core::security::SecurityProfile;
use nix::unistd::Uid;
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real cgroup/container requires root in this environment");
        return false;
    }
    true
}

fn pull_busybox(store: &Store) -> bool {
    if let Err(e) = registry::pull(store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return false;
    }
    true
}

/// Parses `/proc/<pid>/status`'s `CapBnd:` line - a 64-bit hex bitmask of
/// the process's capability bounding set (see `capabilities(7)`). Bit
/// numbers are the same stable ABI values the kernel and every
/// capability-aware tool (including the `caps` crate this project uses)
/// agree on - not something specific to this test.
fn capability_bounding_set(pid: i32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read /proc/<pid>/status");
    let line = status.lines().find(|l| l.starts_with("CapBnd:")).expect("no CapBnd: line");
    let hex = line.split_whitespace().nth(1).unwrap();
    u64::from_str_radix(hex, 16).expect("CapBnd: value should be hex")
}

/// `start()` returning only guarantees the child's pid exists and was
/// recorded as running - not that `run_container_init`'s own setup
/// (mounts, capability-dropping, seccomp, then finally `execve`) has
/// actually finished running yet, all of which take real wall time. This
/// polls `/proc/<pid>/comm` until it reads `want` (the eventually-exec'd
/// binary's own name) - the only reliable signal that the *entire* init
/// sequence, including the capability drop this test is about to
/// inspect, has completed.
///
/// Deliberately not "until comm stops reading kiln": that only holds
/// when this is driven through the real `kiln` binary. Called from a
/// test binary instead (as here), the freshly-cloned child's `comm`
/// before `execve` is the *test binary's own* (truncated) name, which
/// already isn't `"kiln"` on the very first check - silently turning
/// that check into a no-op that doesn't wait for anything at all.
fn wait_for_exec(pid: i32, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim() == want {
            return;
        }
        if Instant::now() > deadline {
            panic!("container process never appeared to execve into {want:?} (last seen comm: {comm:?})");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const CAP_CHOWN_BIT: u32 = 0;
const CAP_SYS_ADMIN_BIT: u32 = 21;

fn wait_for_exit(store: &Store, id: &str) -> Container {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(c) = Container::load(store, id) {
            let mut c = c;
            c.refresh(store);
            if !matches!(c.status, kiln_cli::container::Status::Running) {
                return c;
            }
        }
        if Instant::now() > deadline {
            panic!("container did not exit within 10s");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn default_profile_excludes_sys_admin_and_includes_the_docker_baseline() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if !pull_busybox(&store) {
        return;
    }

    let mut spec = RunSpec::new("busybox:latest");
    spec.command = vec!["sleep".to_string(), "30".to_string()];
    let container = start(&store, spec, None).expect("start");
    let pid = container.pid.expect("Running implies pid");
    wait_for_exec(pid, "sleep");

    let bounding = capability_bounding_set(pid);

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);

    assert_eq!(
        bounding & (1 << CAP_SYS_ADMIN_BIT),
        0,
        "CAP_SYS_ADMIN must not be in the default bounding set (CapBnd={bounding:#x})"
    );
    assert_ne!(
        bounding & (1 << CAP_CHOWN_BIT),
        0,
        "CAP_CHOWN is part of the default baseline and should still be in the bounding set (CapBnd={bounding:#x})"
    );
}

#[test]
fn cap_add_widens_the_bounding_set_explicitly() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if !pull_busybox(&store) {
        return;
    }

    let mut spec = RunSpec::new("busybox:latest");
    spec.command = vec!["sleep".to_string(), "30".to_string()];
    spec.security = SecurityProfile { cap_add: vec!["SYS_ADMIN".to_string()], ..Default::default() };
    let container = start(&store, spec, None).expect("start");
    let pid = container.pid.expect("Running implies pid");
    wait_for_exec(pid, "sleep");

    let bounding = capability_bounding_set(pid);

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);

    assert_ne!(
        bounding & (1 << CAP_SYS_ADMIN_BIT),
        0,
        "--cap-add SYS_ADMIN should put CAP_SYS_ADMIN back in the bounding set (CapBnd={bounding:#x})"
    );
}

#[test]
fn default_profile_blocks_mount_from_inside_the_container() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if !pull_busybox(&store) {
        return;
    }

    let mut spec = RunSpec::new("busybox:latest");
    // Redirects the mount attempt's own stderr into stdout so the
    // container's captured log (this test's only window into what
    // happened, since it never inspects the process while running) shows
    // the kernel's actual denial message, then an explicit exit code
    // marker `sh` itself computes - `mount`'s own exit code alone
    // wouldn't survive being the last command in a script reliably
    // across busybox's ash.
    spec.command = vec!["sh".to_string(), "-c".to_string(), "mount -t tmpfs tmpfs /tmp 2>&1; echo EXIT:$?".to_string()];
    let container = start(&store, spec, None).expect("start");

    let exited = wait_for_exit(&store, &container.id);
    let log = std::fs::read_to_string(Container::log_path(&store, &exited.id)).unwrap_or_default();

    kiln_cli::cgroup::remove(&exited.id);

    assert!(
        !log.contains("EXIT:0"),
        "mount should have failed (blocked by seccomp and/or the dropped CAP_SYS_ADMIN), but the container reported success: {log:?}"
    );
    assert!(
        log.to_lowercase().contains("permitted") || log.to_lowercase().contains("permission"),
        "expected a permission-denied-shaped message from the blocked mount(2) call, got: {log:?}"
    );
}
