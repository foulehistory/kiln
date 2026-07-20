//! `kiln stop` - the CLI counterpart of `kilnd`'s `POST /containers/:id/stop`.
//! Both now share [`stop_container`] rather than duplicating the
//! SIGTERM/grace-period/SIGKILL dance - that duplication (kilnd had it,
//! the CLI didn't) is exactly how kilnd's copy briefly regressed to a
//! SIGTERM-only version that silently did nothing.

use crate::container::Container;
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use std::time::Duration;

#[derive(clap::Args, Debug)]
pub struct Args {
    pub containers: Vec<String>,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    for name in &args.containers {
        match stop_container(store, name) {
            Ok(c) => println!("{}", c.id),
            Err(e) => eprintln!("kiln: stopping {name}: {e}"),
        }
    }
    Ok(())
}

/// True once `id`'s cgroup has no resident processes left - how [`stop_container`]
/// tells whether `SIGTERM` actually worked before deciding whether to escalate.
fn cgroup_is_empty(id: &str) -> bool {
    crate::cgroup::open(id)
        .and_then(|dir| std::fs::read_to_string(dir.join("cgroup.procs")).ok())
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
}

/// Stop a running container: `SIGTERM`, a short grace period polling the
/// cgroup for exit, then `SIGKILL` if it's still alive.
///
/// `SIGTERM` alone is not reliable: a container's command runs as PID 1 of
/// its own PID namespace (kiln has no separate init layer - see
/// `run.rs`'s module docs), and per `pid_namespaces(7)`, a namespace's
/// PID 1 silently discards any signal whose default action is "terminate"
/// unless it explicitly installed a handler for that exact signal. Most
/// commands never do that for `SIGTERM`, so without the `SIGKILL`
/// fallback this would report success (the `kill(2)` syscall itself does
/// succeed) while the container just kept running. `docker stop` has the
/// identical two-step shape for the identical reason.
pub fn stop_container(store: &Store, id_or_name: &str) -> CliResult<Container> {
    let mut c = Container::resolve(store, id_or_name).ok_or_else(|| CliError::msg(format!("no such container: {id_or_name}")))?;
    let Some(pid) = c.pid else {
        return Ok(c);
    };
    let pid = nix::unistd::Pid::from_raw(pid);

    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);

    let mut exited = false;
    for _ in 0..50 {
        if cgroup_is_empty(&c.id) {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !exited {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    }

    // No separate step needed to stop routing published ports: the relay
    // listener lives inside the per-container supervisor process (see
    // network::spawn_port_forwarder's docs), which exits on its own once
    // it observes (via waitpid) that the container process above is gone.

    c.refresh(store);
    Ok(c)
}
