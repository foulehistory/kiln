//! `kiln exec` - run a command inside an already-running container by
//! joining its namespaces (`setns(2)`) rather than creating a new one.
//! See `kilnd_core::namespaces::join_namespaces` for the mechanics.
//!
//! The *user* namespace is joined like any other: overlayfs mounted from
//! within a non-initial user namespace refuses reads (not just writes) to
//! a caller outside that namespace, regardless of the target file's own
//! permission bits - so without joining it, even `cat /etc/passwd` (a
//! perfectly world-readable file inside the container) comes back
//! `EACCES`. `"user"` is joined first, before `mnt`/`pid`/etc: per
//! `setns(2)`, joining a user namespace before the namespaces it owns is
//! the safe order, since capability checks for joining those can then
//! resolve through membership already established. Real root joining a
//! *descendant* user namespace (which a container's always is, relative
//! to the real root that started `kiln exec`) is always permitted.

use crate::container::{Container, Status};
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use kilnd_core::namespaces::join_namespaces;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;

#[derive(clap::Args, Debug)]
pub struct Args {
    pub container: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let mut container = Container::resolve(store, &args.container).ok_or_else(|| CliError::msg(format!("no such container: {}", args.container)))?;
    container.refresh(store);
    if container.status != Status::Running {
        return Err(CliError::msg(format!("container {} is not running", container.id)));
    }
    if args.command.is_empty() {
        return Err(CliError::msg("exec requires a command"));
    }
    let pid = Pid::from_raw(container.pid.expect("Running implies pid is set"));

    // user/mnt/uts/ipc/net take effect on this process immediately; pid
    // only affects processes forked *after* this point - which is exactly
    // what the fork below is for.
    join_namespaces(pid, &["user", "mnt", "uts", "ipc", "net", "pid"])?;

    // Become "namespace uid/gid 0" for real, same as a freshly-created
    // container does (see run.rs::run_container_init) - setns(user) alone
    // only makes us a *member* of the container's user namespace, it
    // doesn't change our credentials within it. setgroups must come
    // first: our real supplementary groups (e.g. group 0, since `kiln
    // exec` itself typically runs as real root) survive the setns and
    // would otherwise make DAC checks use group permission bits instead
    // of "other" on any container-root-owned path.
    nix::unistd::setgroups(&[]).map_err(|e| CliError::msg(format!("setgroups: {e}")))?;
    nix::unistd::setresgid(
        nix::unistd::Gid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
    )
    .map_err(|e| CliError::msg(format!("setresgid: {e}")))?;
    nix::unistd::setresuid(
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Uid::from_raw(0),
    )
    .map_err(|e| CliError::msg(format!("setresuid: {e}")))?;

    let _ = nix::unistd::chdir("/");

    match unsafe { fork() }.map_err(|e| CliError::msg(format!("fork: {e}")))? {
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).map_err(|e| CliError::msg(format!("waitpid: {e}")))?;
            let code = match status {
                WaitStatus::Exited(_, code) => code,
                WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                _ => -1,
            };
            std::process::exit(code);
        }
        ForkResult::Child => {
            let args_c: Vec<CString> = args
                .command
                .iter()
                .map(|s| CString::new(s.as_str()).expect("command has a NUL byte"))
                .collect();
            let err = nix::unistd::execvp(&args_c[0], &args_c);
            eprintln!("kiln: exec {:?}: {:?}", args.command[0], err);
            std::process::exit(127);
        }
    }
}
