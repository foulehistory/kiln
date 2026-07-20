//! `--restart on-failure`: a crashing container's supervisor should relaunch
//! it under the same id, not just record it as exited. The command itself
//! exits (almost) instantly, so the observable signal is that its pid keeps
//! changing across a short wait window rather than staying fixed.

use kiln_cli::commands::run::{start, RunSpec};
use kiln_cli::container::{Container, RestartPolicy};
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real cgroup/container requires root in this environment");
        return false;
    }
    true
}

#[test]
fn on_failure_restart_relaunches_a_crashing_container_under_the_same_id() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let mut spec = RunSpec::new("scratch");
    // No such binary in an empty rootfs: the container's own process fails
    // to exec and exits non-zero almost immediately - exactly the crash
    // loop `on-failure` exists to handle.
    spec.command = vec!["/nonexistent".to_string()];
    spec.restart_policy = RestartPolicy::OnFailure;

    let container = start(&store, spec, None).expect("start");
    let first_pid = container.pid.expect("Running implies pid");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut relaunched_pid = None;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        if let Some(c) = Container::load(&store, &container.id) {
            if let Some(pid) = c.pid {
                if pid != first_pid {
                    relaunched_pid = Some(pid);
                    break;
                }
            }
        }
    }
    assert!(
        relaunched_pid.is_some(),
        "supervisor should have relaunched the crashing container with a new pid"
    );

    // Disable the policy before cleanup, or the container the `stop` below
    // kills would just get relaunched again by its own supervisor - the
    // same reason `docker stop` on an `--restart always` container comes
    // back too, unless the policy is cleared first.
    if let Some(mut c) = Container::load(&store, &container.id) {
        c.restart_policy = RestartPolicy::No;
        c.save(&store).unwrap();
    }
    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);
}
