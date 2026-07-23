//! The per-container supervisor: what makes `kiln run -d` (detached,
//! persistent) containers possible **without** a persistent daemon.
//!
//! The hard problem with "daemonless" detached containers is: once `kiln
//! run -d` prints the container id and exits, who calls `waitpid(2)` on
//! it to learn its real exit status later? If nothing does, the container
//! becomes a zombie reparented to PID 1 (init), silently reaped with its
//! exit code lost forever - `kiln ps`/`kiln logs` would have no way to
//! tell "still running" from "exited successfully" from "crashed".
//!
//! The fix used here (the same idea behind Podman's `conmon` and
//! containerd's per-container shims) is a **short-lived supervisor**: one
//! extra process, forked right before the container itself, that
//! `setsid()`s to detach from the terminal, creates the real container,
//! records its pid, then blocks on `waitpid` for exactly that one
//! container. When the container exits, the supervisor writes the real
//! exit code into the container's state file and exits itself. It is not
//! a background service - it exists only for the lifetime of the one
//! container it supervises, so "daemonless" still holds: there is nothing
//! left running when no containers are.

use crate::container::{now_unix, Container, Status};
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use kilnd_core::namespaces::{spawn_paused, Spawn};
use nix::unistd::{fork, pipe, ForkResult};
use std::os::fd::AsRawFd;

/// How long a container must run before a subsequent crash is treated as
/// a *new* crash loop rather than a continuation of the current one -
/// see the backoff reset in the exit-handling block below.
const STABLE_UPTIME_SECS: u64 = 10;

/// `min(60, 2^restart_count)` seconds - 1s, 2s, 4s, ... up to a 60s cap.
/// Crude but effective: enough to stop a persistently-crashing container
/// from spinning as fast as the kernel can fork, without needing a full
/// token-bucket rate limiter for what's still a fairly narrow use case.
fn backoff_delay_secs(restart_count: u32) -> u64 {
    1u64.checked_shl(restart_count.min(6)).unwrap_or(64).min(60)
}

/// Start `container` (whose `pid`/`status` are not yet set) detached,
/// returning it once its supervisor confirms it actually started (with
/// `pid`/`status` filled in and already persisted to `store`).
///
/// `post_spawn`, if given, runs after the container's namespaces exist
/// (so e.g. `commands::network::attach_container` can wire up a veth
/// pair into its net namespace) but before it's released to actually run -
/// see [`kilnd_core::namespaces::spawn_paused`]. Its `Ok` value, if
/// `Some((network, ip))`, is stashed as the container's `network`/`ip`
/// before the initial state is persisted.
pub fn spawn_detached<F>(
    store: &Store,
    mut container: Container,
    opts: &Spawn,
    child_fn: F,
    post_spawn: Option<impl FnOnce(&Store, i32) -> CliResult<Option<(String, String)>>>,
) -> CliResult<Container>
where
    F: FnMut() -> kilnd_core::Result<()>,
{
    let (read_end, write_end) = pipe().map_err(|e| CliError::msg(format!("pipe: {e}")))?;

    match unsafe { fork() }.map_err(|e| CliError::msg(format!("fork: {e}")))? {
        ForkResult::Parent { .. } => {
            drop(write_end);
            let mut buf = [0u8; 1];
            let mut got = 0;
            while got < 1 {
                let n =
                    nix::unistd::read(read_end.as_raw_fd(), &mut buf[got..]).map_err(|e| CliError::msg(format!("reading supervisor ack: {e}")))?;
                if n == 0 {
                    return Err(CliError::msg("supervisor exited before the container started"));
                }
                got += n;
            }
            if buf[0] != 1 {
                return Err(CliError::msg("container failed to start (see stderr above)"));
            }
            Container::load(store, &container.id).ok_or_else(|| CliError::msg("container state missing right after start"))
        }
        ForkResult::Child => {
            drop(read_end);
            // Detach: new session, no controlling terminal. This is what
            // lets the supervisor outlive `kiln run`'s own process (and
            // the shell/terminal that invoked it) once the parent exits.
            let _ = nix::unistd::setsid();

            // Close inherited stdin/stdout. This is not cosmetic: this
            // process (and, via the next clone(), the container's own
            // process) still holds open copies of whatever fds `kiln run`
            // had - including, when invoked as `x=$(kiln run -d ...)`,
            // the *write end of the pipe the shell is reading the
            // command substitution's output from*. A shell's `$(...)`
            // only returns once it sees EOF on that pipe, which only
            // happens once *every* process holding a copy of the write
            // end has closed it. `kiln run` itself exits almost
            // immediately, but without this, the supervisor (alive for
            // the container's entire lifetime) and the container process
            // itself would keep an inherited copy open the whole time,
            // silently hanging the shell's command substitution until the
            // container exits - defeating the entire point of `-d`.
            //
            // Deliberately NOT touching fd 2 (stderr): only stdout is
            // what `$(...)` captures, so only stdout needs closing to fix
            // that hang. Redirecting stderr too would silently swallow
            // every error message a container setup failure ever
            // produces (namespace/mount/cgroup failures all `eprintln!`
            // before exiting) - a real bug this project hit once already
            // and lost real debugging time to.
            if let Ok(null_fd) = nix::fcntl::open("/dev/null", nix::fcntl::OFlag::O_RDWR, nix::sys::stat::Mode::empty()) {
                let _ = nix::unistd::dup2(null_fd, 0);
                let _ = nix::unistd::dup2(null_fd, 1);
                if null_fd > 2 {
                    let _ = nix::unistd::close(null_fd);
                }
            }

            let started = match spawn_paused(opts, child_fn) {
                Ok(pending) => {
                    let pid = pending.pid();
                    let hook_result = match post_spawn {
                        Some(hook) => match hook(store, pid.as_raw()) {
                            Ok(net_ip) => Some(net_ip),
                            Err(e) => {
                                eprintln!("kiln: post-spawn setup: {e}");
                                None
                            }
                        },
                        None => Some(None),
                    };
                    if let Some(net_ip) = hook_result {
                        match pending.release() {
                            Ok(()) => {
                                container.pid = Some(pid.as_raw());
                                container.status = Status::Running;
                                container.last_started_at = Some(now_unix());
                                container.health = crate::container::HealthStatus::Starting;
                                if let Some((network, ip)) = net_ip {
                                    container.network = Some(network);
                                    container.ip = Some(ip);
                                }
                                container.save(store).is_ok()
                            }
                            Err(e) => {
                                eprintln!("kiln: releasing container: {e}");
                                false
                            }
                        }
                    } else {
                        false
                    }
                }
                Err(e) => {
                    eprintln!("kiln: starting container: {e}");
                    false
                }
            };

            let _ = nix::unistd::write(&write_end, &[u8::from(started)]);
            drop(write_end);
            if !started {
                std::process::exit(1);
            }

            let pid = nix::unistd::Pid::from_raw(container.pid.expect("set above"));

            // Runs alongside this thread's own `waitpid` below, for as
            // long as the container is `Running` - see
            // `crate::healthcheck::run_loop`'s own docs. No handle is
            // kept: the thread notices on its own once the container's
            // persisted status stops being `Running` and returns.
            if let Some(hc) = container.healthcheck.clone() {
                let store_root = store.root().to_path_buf();
                let id = container.id.clone();
                let raw_pid = pid.as_raw();
                std::thread::spawn(move || {
                    if let Ok(hc_store) = Store::open(&store_root) {
                        crate::healthcheck::run_loop(&hc_store, &id, raw_pid, hc);
                    }
                });
            }

            let exit_code = match nix::sys::wait::waitpid(pid, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => code,
                Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                _ => -1,
            };

            // Distinguish "the kernel OOM-killed this for exceeding its
            // memory.max" from any other reason the process died with
            // SIGKILL (`kiln stop`'s fallback, `kiln rm -f`) - dmesg alone
            // isn't visible via `kiln logs`, so this is the only way a
            // user driving the CLI/dashboard ever sees which one happened.
            // Read *before* the exit is persisted below, and before
            // `restart` (if triggered) recreates the cgroup fresh for the
            // next run.
            let oom_killed = crate::cgroup::open(&container.id)
                .map(kilnd_core::cgroups::CgroupV2::from_existing)
                .and_then(|cg| cg.oom_kill_count().ok())
                .is_some_and(|n| n > 0);
            let mut restart_policy = container.restart_policy;
            let mut restart_count = container.restart_count;
            if let Some(mut c) = Container::load(store, &container.id) {
                c.status = Status::Exited(exit_code);
                c.last_exit_oom_killed = oom_killed;
                // A run that lasted long enough is treated as stable: the
                // next crash (if any) starts a fresh backoff sequence
                // instead of continuing to back off as if this were still
                // the same crash loop from a while ago.
                let uptime = c.last_started_at.map(|t| now_unix().saturating_sub(t)).unwrap_or(0);
                if uptime >= STABLE_UPTIME_SECS {
                    c.restart_count = 0;
                }
                let _ = c.save(store);
                restart_policy = c.restart_policy;
                restart_count = c.restart_count;
            }

            // `--restart always`/`on-failure`: rather than looping inside
            // this same process, hand off to a *fresh*
            // `commands::run::restart` call - it already does exactly
            // "relaunch this id, reusing its writable state", forking its
            // own new detached supervisor that outlives this one. This
            // process still exits normally right after, so there's never
            // a moment with two supervisors both watching the same
            // container. The delay backs off exponentially with
            // `restart_count` (see `backoff_delay_secs`) rather than a
            // flat retry interval, to keep a persistently-crashing
            // container from spinning as fast as the kernel can fork.
            if restart_policy.should_restart(exit_code) {
                std::thread::sleep(std::time::Duration::from_secs(backoff_delay_secs(restart_count)));
                if let Some(mut c) = Container::load(store, &container.id) {
                    c.restart_count = c.restart_count.saturating_add(1);
                    let _ = c.save(store);
                }
                // `restart` reads `last_exit_oom_killed` (just persisted
                // above) itself and carries an OOM notice across the log
                // truncation it's about to do - see
                // `commands::run::RunSpec::log_preamble`'s own docs on why
                // that write has to happen there, through the same file
                // handle the new run's stdout/stderr get `dup2`'d from,
                // rather than racing it from here with a second one.
                if let Err(e) = crate::commands::run::restart(store, &container.id) {
                    eprintln!("kiln: restart policy: relaunching {}: {e}", container.id);
                }
            } else if oom_killed {
                // No restart coming: the container stays exited, so
                // there's no live process left that could race this
                // append - safe to just write it directly.
                if let Ok(mut log) = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(Container::log_path(store, &container.id))
                {
                    use std::io::Write;
                    let _ = writeln!(log, "kiln: container killed by the kernel OOM killer (memory.max exceeded)");
                }
            }
            std::process::exit(0);
        }
    }
}
