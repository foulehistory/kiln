//! Verifies cgroups v2 limits are actually enforced on a real, isolated
//! process: a container that requests 32 MiB of memory and then tries to
//! allocate and touch far more must be killed by the kernel's OOM killer
//! for that cgroup, not merely "asked nicely" to stay under the limit.

use kilnd_core::cgroups::{ensure_delegated_root, CgroupV2, Limits};
use kilnd_core::namespaces::{spawn_paused, Namespaces, Spawn};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Uid;
use std::path::Path;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: writing to /sys/fs/cgroup requires root in this environment");
        return false;
    }
    true
}

#[test]
fn memory_limit_is_enforced_by_the_kernel() {
    if !require_root() {
        return;
    }

    let mount_root = Path::new("/sys/fs/cgroup");
    let kiln_root = ensure_delegated_root(mount_root, "kiln-test").expect("delegate controllers to kiln-test");

    let id = format!("memtest-{}", std::process::id());
    let limits = Limits {
        memory_max_bytes: Some(32 * 1024 * 1024),
        // Without this, the kernel just swaps out this test's cold pages
        // under memory pressure instead of invoking the OOM killer - see
        // the doc comment on `memory_swap_max_bytes`.
        memory_swap_max_bytes: Some(0),
        pids_max: Some(64),
        ..Limits::default()
    };
    let cgroup = CgroupV2::create(&kiln_root, &id, &limits).expect("create cgroup");

    // No mount/user/uts/ipc/net isolation needed for this test - just a
    // plain child process (still its own PID namespace so it can't be
    // confused with anything else) that we can drop straight into the
    // cgroup before it starts allocating.
    let opts = Spawn {
        namespaces: Namespaces {
            pid: true,
            mount: false,
            uts: false,
            ipc: false,
            net: false,
            user: false,
        },
        ..Spawn::default()
    };

    // spawn_paused (rather than spawn_isolated) so the child is placed
    // into the memory-limited cgroup *before* it runs a single
    // instruction of its allocation loop below. Using spawn_isolated here
    // would race the child's own execution against add_process() below,
    // and a fast child can easily finish allocating before losing that
    // race, defeating the whole point of the test.
    let pending = spawn_paused(&opts, || {
        // Touch 256 MiB, 1 MiB at a time, forcing the kernel to actually
        // back each page - a limit that only capped `malloc` bookkeeping
        // without touching pages would not catch this.
        let chunk = 1024 * 1024;
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for _ in 0..256 {
            let mut v = vec![0u8; chunk];
            for b in v.iter_mut().step_by(4096) {
                *b = 1;
            }
            blocks.push(v);
        }
        std::hint::black_box(&blocks);
        Ok(())
    })
    .expect("spawn_paused");

    let child_pid = pending.pid();
    cgroup.add_process(child_pid).expect("add_process");
    assert_eq!(cgroup.processes().expect("processes"), vec![child_pid]);
    pending.release().expect("release");

    match waitpid(child_pid, None).expect("waitpid") {
        WaitStatus::Signaled(_, Signal::SIGKILL, _) => {}
        other => panic!("expected the memory cgroup's OOM killer to SIGKILL the child, got {other:?}"),
    }

    let mem_events = std::fs::read_to_string(cgroup.path().join("memory.events")).expect("memory.events");
    let oom_kills: u64 = mem_events
        .lines()
        .find(|l| l.starts_with("oom_kill "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(oom_kills >= 1, "memory.events should record the OOM kill");

    cgroup.remove().expect("remove cgroup");
}

#[test]
fn cpu_and_memory_limits_round_trip_through_cgroupfs() {
    if !require_root() {
        return;
    }

    let mount_root = Path::new("/sys/fs/cgroup");
    let kiln_root = ensure_delegated_root(mount_root, "kiln-test").expect("delegate controllers to kiln-test");

    let id = format!("limits-{}", std::process::id());
    let limits = Limits {
        cpu_max_us: Some(50_000),
        cpu_period_us: 100_000,
        memory_max_bytes: Some(64 * 1024 * 1024),
        memory_swap_max_bytes: Some(0),
        pids_max: Some(16),
        ..Limits::default()
    };
    let cgroup = CgroupV2::create(&kiln_root, &id, &limits).expect("create cgroup");

    let cpu_max = std::fs::read_to_string(cgroup.path().join("cpu.max")).unwrap();
    assert_eq!(cpu_max.trim(), "50000 100000");

    let mem_max = std::fs::read_to_string(cgroup.path().join("memory.max"))
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap();
    assert_eq!(mem_max, 64 * 1024 * 1024);

    let pids_max = std::fs::read_to_string(cgroup.path().join("pids.max")).unwrap();
    assert_eq!(pids_max.trim(), "16");

    cgroup.remove().expect("remove cgroup");
}
