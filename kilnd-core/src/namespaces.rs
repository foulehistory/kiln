//! Process isolation via Linux namespaces.
//!
//! A Kiln container is, at its core, a single process created with
//! `clone(2)` and a combination of `CLONE_NEW*` flags. This module owns
//! that one syscall and the bookkeeping required to make it produce a
//! correctly isolated, correctly identified process:
//!
//! - **`CLONE_NEWPID`** — the cloned process becomes PID 1 of a brand new
//!   PID namespace. Unlike `unshare(CLONE_NEWPID)` (which only affects the
//!   *caller's future children*, not the caller itself), passing this flag
//!   to `clone(2)` puts the newly created process itself into the new
//!   namespace immediately. That is why Kiln uses `clone()` rather than
//!   `fork()` + `unshare()`.
//! - **`CLONE_NEWNS`** — a private mount table, so mounts performed inside
//!   the container (overlayfs rootfs, `/proc`, `/dev`, ...) never appear on
//!   the host and vice versa.
//! - **`CLONE_NEWUTS`** — a private hostname/domainname, set via
//!   `sethostname(2)` once the child is running.
//! - **`CLONE_NEWIPC`** — a private System V IPC / POSIX message queue
//!   namespace, so containers can't see or signal each other's IPC objects.
//! - **`CLONE_NEWNET`** — a private network stack (starts with only `lo`,
//!   down). Wiring it up to a bridge is `network.rs`'s job, not this
//!   module's.
//! - **`CLONE_NEWUSER`** — a private UID/GID space. This is what lets a
//!   process be "root" (UID 0) *inside* the container while remaining an
//!   unprivileged UID on the host, which is the basis of Kiln's rootless
//!   security model.
//!
//! # The `CLONE_NEWUSER` synchronization problem
//!
//! `CLONE_NEWUSER` introduces a subtlety documented in `user_namespaces(7)`:
//! the moment `clone(2)` returns in the child, that child owns the new user
//! namespace and has a *full capability set inside it* — but its UID/GID,
//! as seen from anywhere, is not yet defined. The kernel reports the
//! "overflow" ID (typically 65534) until someone writes a mapping to
//! `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`. Crucially, **that write
//! can only be done by a process outside the new user namespace** (the
//! parent) — the child cannot write its own map. So the child must block
//! until the parent has done this, or any code that depends on the
//! container's mapped identity (e.g. `setuid(0)`, or file ownership checks
//! against the mapped UID) will observe the wrong thing or fail outright.
//!
//! Kiln implements this with a pipe: the child's very first action is a
//! blocking `read(2)` on the pipe's read end; the parent writes the ID maps
//! and then a single byte to release it. This is the same handshake
//! `runc`/`youki`/`user_namespaces(7)`'s own example code use.
//!
//! # Why `clone(2)` and not `fork(2)` + `unshare(2)`
//!
//! `fork()` always leaves the child in the *same* PID namespace as the
//! parent; only a subsequently-forked grandchild would land in a new PID
//! namespace after `unshare(CLONE_NEWPID)`. Doing it in one `clone(2)` call
//! avoids that extra hop and the extra process it would require.

use crate::error::{self, Result};
use nix::sched::CloneFlags;
use nix::unistd::Pid;
use std::os::fd::AsRawFd;

/// One line of `/proc/<pid>/{uid,gid}_map`: map `count` contiguous IDs
/// starting at `container_id` (as seen inside the new namespace) to
/// `host_id` (as seen everywhere else, including by the kernel itself).
///
/// Note: writing more than one line, or a line that does not simply map
/// the writer's own ID, requires the *writing* process to hold
/// `CAP_SETUID`/`CAP_SETGID` in the parent (host) user namespace — i.e. it
/// requires Kiln itself to be running as root, or to delegate through the
/// `newuidmap`/`newgidmap` setuid helpers (consulting `/etc/subuid` /
/// `/etc/subgid`), which is not yet wired up. Unprivileged callers must
/// currently stick to a single self-mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub count: u32,
}

/// Which namespaces to isolate the new process into. Every field maps
/// directly to one `CLONE_NEW*` flag; see the module docs for what each
/// one buys you.
#[derive(Debug, Clone, Copy)]
pub struct Namespaces {
    pub pid: bool,
    pub mount: bool,
    pub uts: bool,
    pub ipc: bool,
    pub net: bool,
    pub user: bool,
}

impl Namespaces {
    /// Isolate into all six namespace types — the default for a real
    /// container.
    pub fn all() -> Self {
        Namespaces {
            pid: true,
            mount: true,
            uts: true,
            ipc: true,
            net: true,
            user: true,
        }
    }

    fn to_clone_flags(self) -> CloneFlags {
        let mut flags = CloneFlags::empty();
        if self.pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.uts {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.ipc {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        flags
    }
}

/// Configuration for spawning an isolated process.
pub struct Spawn {
    pub namespaces: Namespaces,
    /// UID mapping for the new user namespace. Ignored if
    /// `namespaces.user` is false. Must be non-empty if `user` is true and
    /// the child needs a defined identity (it almost always does).
    pub uid_map: Vec<IdMap>,
    pub gid_map: Vec<IdMap>,
    /// Hostname to set inside the new UTS namespace, if any.
    pub hostname: Option<String>,
    /// Size in bytes of the stack handed to `clone(2)` for the child's
    /// initial execution. 8 MiB matches the default Linux thread stack
    /// size and comfortably covers the setup code that runs before the
    /// child execve's into the container's real entrypoint.
    pub stack_size: usize,
}

impl Default for Spawn {
    fn default() -> Self {
        Spawn {
            namespaces: Namespaces::all(),
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            hostname: None,
            stack_size: 8 * 1024 * 1024,
        }
    }
}

fn write_id_map(pid: Pid, file: &str, mappings: &[IdMap]) -> Result<()> {
    let path = format!("/proc/{pid}/{file}");
    let mut body = String::new();
    for m in mappings {
        body.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.count));
    }
    std::fs::write(&path, body).map_err(error::io(path))
}

/// A freshly-`clone()`d process, blocked on a pipe read and waiting for
/// [`PendingChild::release`] before it runs `child_fn` (or even sets its
/// hostname). This gap exists so the parent can do things that must
/// happen *before the child gets to run any code at all* — writing its
/// uid/gid maps (mandatory if `namespaces.user` is set: the child cannot
/// write its own maps), but also, e.g., placing it into a cgroup before it
/// has a chance to allocate memory or spawn threads a limit is meant to
/// catch. Without this gate that placement would race the child.
pub struct PendingChild {
    pid: Pid,
    write_end: std::os::fd::OwnedFd,
}

impl PendingChild {
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Let the child proceed. Consumes `self`: the handshake is one-shot.
    pub fn release(self) -> Result<()> {
        nix::unistd::write(&self.write_end, &[1u8]).map_err(error::syscall("write"))?;
        Ok(())
    }
}

/// Like [`spawn_isolated`], but returns as soon as `clone(2)` returns and
/// the id maps (if any) have been written, *before* releasing the child to
/// actually run `child_fn`. Callers that need to act on the child (e.g.
/// [`crate::cgroups::CgroupV2::add_process`]) before it starts running
/// must use this and call [`PendingChild::release`] themselves once ready;
/// [`spawn_isolated`] is just this function followed by an immediate
/// release, for the common case that doesn't need the gap.
pub fn spawn_paused<F>(opts: &Spawn, mut child_fn: F) -> Result<PendingChild>
where
    F: FnMut() -> Result<()>,
{
    // Synchronization pipe: the child's very first action is a blocking
    // read on this; nothing else it does (setting its hostname, running
    // child_fn) starts until the parent calls `release()`. Both ends
    // survive the clone() as independent fd table entries pointing at the
    // same underlying pipe, which is what makes this ordinary
    // fork-and-pipe pattern work across the syscall.
    let (read_end, write_end) = nix::unistd::pipe().map_err(error::syscall("pipe"))?;
    let read_fd = read_end.as_raw_fd();
    let write_fd = write_end.as_raw_fd();

    let hostname = opts.hostname.clone();

    let run_child = move || -> isize {
        // We never write to the pipe; drop our copy of the write end so
        // the only writer left is the parent.
        let _ = nix::unistd::close(write_fd);

        let mut buf = [0u8; 1];
        loop {
            match nix::unistd::read(read_fd, &mut buf) {
                Ok(_) => break,
                Err(nix::Error::EINTR) => continue,
                Err(e) => {
                    eprintln!("kiln: container child: waiting for release failed: {e}");
                    return 1;
                }
            }
        }
        let _ = nix::unistd::close(read_fd);

        if let Some(name) = &hostname {
            if let Err(e) = nix::unistd::sethostname(name) {
                eprintln!("kiln: container child: sethostname failed: {e}");
                return 1;
            }
        }

        match child_fn() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("kiln: container child failed: {e}");
                1
            }
        }
    };

    let cb: nix::sched::CloneCb = Box::new(run_child);
    let mut stack = vec![0u8; opts.stack_size];
    let flags = opts.namespaces.to_clone_flags();

    // Safety: `stack` is large enough for the setup code above plus
    // whatever `child_fn` does (callers doing heavier work, e.g.
    // execve-ing a real container entrypoint, replace the address space
    // entirely at that point, so the depth this stack ever needs to
    // support is bounded by `child_fn` itself). `CLONE_VM` is not among
    // our flags, so the child receives a private copy-on-write copy of
    // this stack and of every other captured value; nothing here is
    // shared or aliased between parent and child after the syscall
    // returns, so it is safe for the parent to let `stack` and the boxed
    // closure go out of scope immediately after.
    let child_pid = unsafe { nix::sched::clone(cb, &mut stack, flags, Some(libc::SIGCHLD)) }.map_err(error::syscall("clone"))?;

    // Parent's own copy of the read end is never used; close it so the
    // pipe has exactly one reader (the child) and one writer (us).
    drop(read_end);

    if opts.namespaces.user {
        if !opts.gid_map.is_empty() {
            write_id_map(child_pid, "gid_map", &opts.gid_map)?;
        }
        if !opts.uid_map.is_empty() {
            write_id_map(child_pid, "uid_map", &opts.uid_map)?;
        }
    }

    Ok(PendingChild { pid: child_pid, write_end })
}

/// Create a new process isolated according to `opts`, run `child_fn`
/// inside it, and return the host-visible [`Pid`] of that process. This is
/// [`spawn_paused`] immediately followed by [`PendingChild::release`]; use
/// `spawn_paused` directly if you need to act on the child (e.g. add it to
/// a cgroup) before it starts running.
///
/// The returned `Pid` is a normal host PID: `clone(2)`'s return value is
/// always meaningful in the *caller's* PID namespace, regardless of what
/// namespace the child now lives in. Use it with `waitpid` as usual.
pub fn spawn_isolated<F>(opts: &Spawn, child_fn: F) -> Result<Pid>
where
    F: FnMut() -> Result<()>,
{
    let pending = spawn_paused(opts, child_fn)?;
    let pid = pending.pid();
    pending.release()?;
    Ok(pid)
}

/// Read the namespace identifier `/proc/<pid>/ns/<kind>` resolves to (e.g.
/// `"pid:[4026532081]"`). Two processes in the same namespace of a given
/// kind always resolve to the same string; this is the standard way to
/// prove (or disprove) namespace isolation from outside, used throughout
/// this crate's integration tests.
pub fn ns_id(pid: Pid, kind: &str) -> Result<String> {
    let path = format!("/proc/{pid}/ns/{kind}");
    std::fs::read_link(&path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(error::io(path))
}

/// Join the calling process (or thread) to the namespaces of an existing
/// process, e.g. to run `kiln exec` inside an already-running container
/// without creating a new one. Each `kind` is one of `"mnt"`, `"uts"`,
/// `"ipc"`, `"net"`, `"pid"`, `"user"` (matching the `/proc/<pid>/ns/`
/// entry names), applied in the order given.
///
/// # PID namespace order matters
///
/// Joining a PID namespace with `setns(2)` does **not** change the
/// calling process's own pid (that's fixed for its lifetime) - it only
/// changes which PID namespace *future children* (via `fork`/`clone`) are
/// born into. So to actually run something *inside* the container's PID
/// namespace, join `"pid"` here and then `fork()`/`clone()` a new child
/// afterward; the calling process itself never "moves". Every other
/// namespace kind takes effect on the calling process immediately.
///
/// # Not joining the user namespace
///
/// This function does not special-case `"user"` beyond joining it like
/// any other kind if asked. Joining a target's user namespace requires
/// the caller to either already be a member of it or have appropriate
/// capabilities in its parent, and afterward the caller's credentials are
/// whatever they already were translated through the new mapping - there
/// is no implicit `setresuid(0)` dance here (contrast with
/// [`spawn_paused`], which owns that handshake for *newly created*
/// namespaces). Callers that need a specific mapped identity after
/// joining must set it explicitly themselves.
pub fn join_namespaces(pid: Pid, kinds: &[&str]) -> Result<()> {
    // Open every /proc/<pid>/ns/<kind> file *before* joining any of
    // them. Joining "mnt" changes which filesystem tree /proc/<pid>
    // itself resolves through for this process: once we're inside the
    // target's mount namespace, /proc is whatever procfs instance is
    // mounted *there* (typically the container's own, PID-namespace-
    // scoped mount) - a host-relative pid like `pid` may not resolve in
    // it at all. Resolving every path up front, while still definitely
    // in our own original mount namespace, avoids that trap entirely.
    let mut files = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let path = format!("/proc/{pid}/ns/{kind}");
        files.push(std::fs::File::open(&path).map_err(error::io(&path))?);
    }
    for file in &files {
        nix::sched::setns(file, CloneFlags::empty()).map_err(error::syscall("setns"))?;
    }
    Ok(())
}
