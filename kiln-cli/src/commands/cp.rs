//! `kiln cp` - copy a file between the host and a *running* container.
//!
//! Reading a container path resolves it through `/proc/<pid>/root/<path>`:
//! the kernel exposes a running process's own merged view of its mount
//! namespace there, so it needs nothing overlay-specific (no reasoning
//! about lower/upper precedence) - just a plain file read, as long as the
//! caller is root (kiln always runs as real root - see the project's
//! identity docs).
//!
//! *Writing* a new file through that same `/proc/<pid>/root/<path>` view
//! doesn't work in this environment: creating a file there hits
//! `EOVERFLOW` from the overlayfs/WSL2 combination this project runs on
//! (reproduced with plain `cp`, not a bug in this code). Writing directly
//! into the container's backing `upper` layer on the host isn't a fix
//! either - overlayfs caches a merged directory's entries once it's
//! mounted, so a file added straight to `upper` from outside the mount
//! can be physically on disk yet invisible through the container's own
//! already-live view of that directory (the kernel's own "concurrent
//! modification of overlayfs branches is unsupported" caveat).
//!
//! So host->container copies instead join the container's `user`+`mnt`
//! namespaces (the same `setns(2)` mechanism `kiln exec` uses) and write
//! through the container's *actual live mount*, in a forked child - see
//! `write_into_container`.
//!
//! A stopped container has no `/proc/<pid>` to resolve through, so it's
//! out of scope for now - `kiln start` it first.

use crate::container::{Container, Status};
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use kilnd_core::namespaces::join_namespaces;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use std::io::Read as _;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// `<container>:<path>` (either side, host<->container) or a plain host path
    pub src: String,
    pub dst: String,
}

enum Endpoint {
    Host(PathBuf),
    Container { id: String, path: String },
}

fn parse_endpoint(s: &str) -> Endpoint {
    // A bare Windows-style drive letter ("C:\...") or a path with no ':'
    // at all is a host path, not a `<container>:<path>` spec - only split
    // on ':' when what's on the left looks like it could be a container
    // name/id (no path separator in it).
    match s.split_once(':') {
        Some((left, right)) if !left.is_empty() && !left.contains('/') && !left.contains('\\') => Endpoint::Container {
            id: left.to_string(),
            path: right.to_string(),
        },
        _ => Endpoint::Host(PathBuf::from(s)),
    }
}

fn resolve_running(store: &Store, id: &str) -> CliResult<Container> {
    let mut c = Container::resolve(store, id).ok_or_else(|| CliError::msg(format!("no such container: {id}")))?;
    c.refresh(store);
    if c.status != Status::Running {
        return Err(CliError::msg(format!(
            "container {id} is not running (cp only works on running containers)"
        )));
    }
    Ok(c)
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let src = parse_endpoint(&args.src);
    let dst = parse_endpoint(&args.dst);

    match (src, dst) {
        (Endpoint::Container { id, path }, Endpoint::Host(host)) => {
            let c = resolve_running(store, &id)?;
            let resolved = format!("/proc/{}/root{}", c.pid.expect("Running implies pid"), path);
            copy_bytes(std::path::Path::new(&resolved), &host)
                .map_err(|e| CliError::msg(format!("copying out of container to {}: {e}", host.display())))?;
        }
        (Endpoint::Host(host), Endpoint::Container { id, path }) => {
            let c = resolve_running(store, &id)?;
            write_into_container(&c, &path, &host).map_err(|e| CliError::msg(format!("copying {} into container: {e}", host.display())))?;
        }
        (Endpoint::Host(_), Endpoint::Host(_)) => {
            return Err(CliError::msg("neither path names a container (expected <container>:<path> on one side)"));
        }
        (Endpoint::Container { .. }, Endpoint::Container { .. }) => {
            return Err(CliError::msg("container-to-container copy isn't supported - copy to the host and back"));
        }
    };

    println!("{}", args.dst);
    Ok(())
}

/// Manual buffered read/write loop instead of `std::fs::copy` *or*
/// `std::io::copy` on two `File`s: both take a specialized fast path on
/// Linux (`copy_file_range`/`sendfile`) that needs the source's size via
/// `fstat`, and WSL2's `/proc` filesystem returns `EOVERFLOW` from that
/// `fstat` when the path is resolved through `/proc/<pid>/root/...` -
/// even though plain `read`/`write` on the same fd work fine. Going
/// through `Read`/`Write` directly (not `io::copy`) is what actually
/// avoids that fast path.
fn copy_bytes(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut src_file = std::fs::File::open(src)?;
    let mut dst_file = std::fs::File::create(dst)?;
    let mut buf = [0u8; 65536];
    loop {
        let n = src_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst_file.write_all(&buf[..n])?;
    }
    Ok(())
}

/// Write `host_src` into the running `container` at `container_path` by
/// forking a child that joins the container's `user`+`mnt` namespaces
/// (same recipe as `kiln exec`, minus `pid`/`uts`/`ipc`/`net` - a plain
/// file write needs neither) and creates the file there directly, so the
/// write goes through the container's actual live overlay mount instead
/// of around it. Bytes cross from the host-reading parent to the
/// namespace-joined child over a pipe.
fn write_into_container(container: &Container, container_path: &str, host_src: &std::path::Path) -> CliResult<()> {
    let mut host_file = std::fs::File::open(host_src).map_err(|e| CliError::msg(format!("opening {}: {e}", host_src.display())))?;
    let (read_end, write_end) = nix::unistd::pipe().map_err(|e| CliError::msg(format!("pipe: {e}")))?;
    let container_pid = nix::unistd::Pid::from_raw(container.pid.expect("Running implies pid"));

    match unsafe { fork() }.map_err(|e| CliError::msg(format!("fork: {e}")))? {
        ForkResult::Parent { child } => {
            drop(read_end);
            let mut buf = [0u8; 65536];
            let mut io_err = None;
            loop {
                match host_file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = nix::unistd::write(&write_end, &buf[..n]) {
                            io_err = Some(format!("writing to pipe: {e}"));
                            break;
                        }
                    }
                    Err(e) => {
                        io_err = Some(format!("reading {}: {e}", host_src.display()));
                        break;
                    }
                }
            }
            drop(write_end);
            let status = waitpid(child, None).map_err(|e| CliError::msg(format!("waitpid: {e}")))?;
            if let Some(e) = io_err {
                return Err(CliError::msg(e));
            }
            match status {
                WaitStatus::Exited(_, 0) => Ok(()),
                _ => Err(CliError::msg("writing the file inside the container's namespace failed")),
            }
        }
        ForkResult::Child => {
            drop(write_end);
            let outcome = (|| -> Result<(), String> {
                join_namespaces(container_pid, &["user", "mnt"]).map_err(|e| format!("join_namespaces: {e}"))?;
                nix::unistd::setgroups(&[]).map_err(|e| format!("setgroups: {e}"))?;
                nix::unistd::setresgid(
                    nix::unistd::Gid::from_raw(0),
                    nix::unistd::Gid::from_raw(0),
                    nix::unistd::Gid::from_raw(0),
                )
                .map_err(|e| format!("setresgid: {e}"))?;
                nix::unistd::setresuid(
                    nix::unistd::Uid::from_raw(0),
                    nix::unistd::Uid::from_raw(0),
                    nix::unistd::Uid::from_raw(0),
                )
                .map_err(|e| format!("setresuid: {e}"))?;
                let _ = nix::unistd::chdir("/");
                let mut dst = std::fs::File::create(container_path).map_err(|e| format!("create {container_path}: {e}"))?;
                let mut buf = [0u8; 65536];
                loop {
                    let n = nix::unistd::read(read_end.as_raw_fd(), &mut buf).map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    use std::io::Write as _;
                    dst.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                }
                Ok(())
            })();
            if let Err(e) = outcome {
                eprintln!("kiln: writing into container: {e}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
    }
}
