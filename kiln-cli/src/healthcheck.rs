//! Background health-probe loop for a container with a configured
//! `healthcheck:` - spawned by the per-container supervisor
//! (`supervisor.rs`) on its own thread, alongside the supervisor's own
//! blocking `waitpid` on the container itself, for as long as the
//! container is running.
//!
//! Probing reuses `kiln exec`'s own join-namespaces mechanism
//! (`commands::exec`'s module docs explain the join order) rather than a
//! second implementation of it - this is the same "run a command inside
//! an already-running container" operation, just invoked as a library
//! call instead of a CLI subcommand, and with a timeout.

use crate::container::{Container, HealthCheckSpec, HealthStatus, Status};
use kiln_image::store::Store;
use kilnd_core::namespaces::join_namespaces;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::time::{Duration, Instant};

/// Runs until `id` is no longer `Status::Running` (checked once per
/// `interval`, since this thread has no other way to learn the container
/// exited - the supervisor's main thread owns the actual `waitpid` on
/// it). Never returns an error: a probe failure just means "unhealthy",
/// not a reason to stop probing.
pub fn run_loop(store: &Store, id: &str, container_pid: i32, spec: HealthCheckSpec) {
    let mut consecutive_failures: u32 = 0;
    loop {
        std::thread::sleep(Duration::from_secs(spec.interval_secs));
        match Container::load(store, id) {
            Some(c) if c.status == Status::Running => {}
            _ => return,
        }

        let healthy = probe_once(container_pid, &spec.test, Duration::from_secs(spec.timeout_secs));
        let new_status = if healthy {
            consecutive_failures = 0;
            HealthStatus::Healthy
        } else {
            consecutive_failures += 1;
            if consecutive_failures < spec.retries.max(1) {
                // Below the failure threshold: a single blip doesn't
                // flip the reported status yet, matching Docker's own
                // `retries` semantics.
                continue;
            }
            HealthStatus::Unhealthy
        };

        if let Some(mut c) = Container::load(store, id) {
            if c.status == Status::Running {
                c.health = new_status;
                let _ = c.save(store);
            }
        }
    }
}

/// Forks, joins `container_pid`'s namespaces, execs `test`, and waits up
/// to `timeout` - killing the probe if it hasn't finished by then.
/// Returns whether it exited with status 0.
fn probe_once(container_pid: i32, test: &[String], timeout: Duration) -> bool {
    if test.is_empty() {
        return false;
    }
    let target = Pid::from_raw(container_pid);
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            if join_namespaces(target, &["user", "mnt", "uts", "ipc", "net", "pid"]).is_err() {
                std::process::exit(127);
            }
            // Become namespace uid/gid 0, same as `kiln exec` - see its
            // own docs on why setgroups must come first.
            let _ = nix::unistd::setgroups(&[]);
            let _ = nix::unistd::setresgid(
                nix::unistd::Gid::from_raw(0),
                nix::unistd::Gid::from_raw(0),
                nix::unistd::Gid::from_raw(0),
            );
            let _ = nix::unistd::setresuid(
                nix::unistd::Uid::from_raw(0),
                nix::unistd::Uid::from_raw(0),
                nix::unistd::Uid::from_raw(0),
            );
            let _ = nix::unistd::chdir("/");

            let Ok(args_c): Result<Vec<CString>, _> = test.iter().map(|s| CString::new(s.as_str())).collect() else {
                std::process::exit(127);
            };
            let _ = nix::unistd::execvp(&args_c[0], &args_c);
            std::process::exit(127);
        }
        Ok(ForkResult::Parent { child }) => wait_with_timeout(child, timeout),
        Err(_) => false,
    }
}

/// Polls `waitpid(..., WNOHANG)` rather than blocking, so a hung probe
/// gets killed at `timeout` instead of wedging this thread (and hence
/// this container's health reporting) indefinitely.
fn wait_with_timeout(child: Pid, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return code == 0,
            Ok(WaitStatus::Signaled(..)) => return false,
            Ok(WaitStatus::StillAlive) => {
                if start.elapsed() >= timeout {
                    let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => return false,
        }
    }
}
