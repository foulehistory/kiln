//! Two real-infrastructure proofs for chantier 4:
//!
//! - `healthcheck_transitions_...`: a real container's `health` actually
//!   flips between `starting`/`unhealthy`/`healthy` as its probe command's
//!   real result changes, not just that `HealthCheckSpec`/`HealthStatus`
//!   round-trip through JSON.
//! - `on_failure_restart_backoff_...`: a real, persistently-crashing
//!   container's successive relaunch delays actually grow (1s, 2s, 4s...)
//!   rather than the flat one-second retry `supervisor.rs` used before
//!   this chantier - the "real induced crash" test this chantier's own
//!   scope calls for.

use kiln_cli::commands::run::{start, RunSpec};
use kiln_cli::container::{Container, HealthCheckSpec, RestartPolicy};
use kiln_image::registry;
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

fn pull_busybox(store: &Store) -> bool {
    if let Err(e) = registry::pull(store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return false;
    }
    true
}

fn wait_for_health(store: &Store, id: &str, want: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    loop {
        if let Some(c) = Container::load(store, id) {
            last = c.health.as_str().to_string();
            if last == want {
                return last;
            }
        }
        if Instant::now() > deadline {
            return last;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn healthcheck_transitions_starting_to_unhealthy_to_healthy_with_a_real_probe() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    if !pull_busybox(&store) {
        return;
    }

    let mut spec = RunSpec::new("busybox:latest");
    spec.command = vec!["sleep".to_string(), "60".to_string()];
    spec.volumes = vec!["healthtest:/data".to_string()];
    spec.healthcheck = Some(HealthCheckSpec {
        test: vec!["test".to_string(), "-f".to_string(), "/data/healthy".to_string()],
        interval_secs: 1,
        timeout_secs: 2,
        retries: 2,
    });

    let container = start(&store, spec, None).expect("start");

    // No /data/healthy yet: the probe fails every second. `retries: 2`
    // means the first failure alone shouldn't flip it to Unhealthy -
    // check that briefly, before waiting for the real Unhealthy
    // transition once the second consecutive failure lands.
    std::thread::sleep(Duration::from_millis(700));
    let mid = Container::load(&store, &container.id).unwrap().health.as_str().to_string();
    assert_eq!(mid, "starting", "a single probe failure shouldn't flip health away from starting yet");

    let unhealthy = wait_for_health(&store, &container.id, "unhealthy", Duration::from_secs(6));
    assert_eq!(
        unhealthy, "unhealthy",
        "container should report unhealthy once retries consecutive probes fail"
    );

    // Real host path backing the container's bind-mounted /data - writing
    // the file here is what a real "the service recovered" event looks
    // like, since it's a live bind mount, not a copy.
    let host_data_dir = kiln_cli::commands::volume::path(&store, "healthtest");
    std::fs::write(host_data_dir.join("healthy"), b"ok").expect("write healthy marker from the host side");

    let healthy = wait_for_health(&store, &container.id, "healthy", Duration::from_secs(4));
    assert_eq!(healthy, "healthy", "container should report healthy once the probe starts succeeding");

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);
}

#[test]
fn on_failure_restart_backoff_grows_between_consecutive_relaunches() {
    if !require_root() {
        return;
    }
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let mut spec = RunSpec::new("scratch");
    // No such binary in an empty rootfs: the container's own process
    // fails to exec and exits non-zero almost immediately, every time -
    // a real, persistent crash loop for the restart policy to react to.
    spec.command = vec!["/nonexistent".to_string()];
    spec.restart_policy = RestartPolicy::OnFailure;

    let container = start(&store, spec, None).expect("start");
    let mut last_pid = container.pid.expect("Running implies pid");
    let mut change_times = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && change_times.len() < 3 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(c) = Container::load(&store, &container.id) {
            if let Some(pid) = c.pid {
                if pid != last_pid {
                    change_times.push(Instant::now());
                    last_pid = pid;
                }
            }
        }
    }

    assert!(
        change_times.len() >= 3,
        "expected at least 3 relaunches within 20s of backoff (1s+2s+4s), only saw {}",
        change_times.len()
    );

    let gap1 = change_times[1].duration_since(change_times[0]);
    let gap2 = change_times[2].duration_since(change_times[1]);
    assert!(
        gap2 > gap1 + Duration::from_millis(500),
        "backoff should grow between relaunches, got gap1={gap1:?} gap2={gap2:?}"
    );

    if let Some(mut c) = Container::load(&store, &container.id) {
        c.restart_policy = RestartPolicy::No;
        c.save(&store).unwrap();
    }
    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);
}
