//! `GET /containers/:id/exec` with `Upgrade: kiln-exec` - an interactive
//! shell inside a running container, streamed over a raw byte connection.
//!
//! This is *not* a real WebSocket (no RFC 6455 framing/masking). That
//! protocol exists to let a generic browser negotiate a bidirectional
//! channel with a server it doesn't otherwise control; here, the only
//! client is `kiln-dashboard`'s own Electron **main** process (Node can
//! speak raw HTTP `Upgrade` natively via its `http` module's `'upgrade'`
//! event), which this project also owns. A raw byte pipe after a classic
//! HTTP `Upgrade` handshake gets the same result with less code and no
//! framing overhead - reasonable here specifically because both ends are
//! ours; a real WebSocket-facing server would need the real protocol.
//!
//! Joins the container's namespaces the same way `kiln exec` does
//! (`kilnd_core::namespaces::join_namespaces`), *including* the user
//! namespace - overlayfs mounted from a non-initial user namespace
//! refuses reads to a caller outside it regardless of permission bits, so
//! skipping this makes the shell unable to read almost anything. Unlike
//! `kiln exec`, this can't happen in the connection-handling thread
//! itself: `setns(2)` on `CLONE_NEWUSER` is refused outright on a
//! multithreaded process, and `kilnd` is exactly that (one thread per
//! connection). So the join (and the credential dance that follows it)
//! happens in the forked child instead, which is single-threaded from the
//! moment `fork()` returns - which also means it gets its own private
//! `fs_struct` for free, without needing the `unshare(CLONE_FS)` the
//! parent thread would otherwise need before it could `setns(mnt)`.
//!
//! Unlike `kiln exec`, the **PID** namespace is not joined either. That's
//! specific to `kilnd` being multi-threaded: `setns(2)`-ing a thread's
//! `pid_ns_for_children` and then having that *same thread* create
//! another thread (not a new process) fails with `EINVAL` - a new thread
//! must stay in lockstep with the rest of its thread group's PID
//! namespace, which a just-changed `pid_ns_for_children` breaks. Since
//! [`shuttle`] below needs a second thread to pump pty output back to the
//! client concurrently with reading client input, joining the PID
//! namespace here isn't an option. The practical cost is cosmetic: the
//! exec'd shell won't show up in the container's *own* `ps`, but its
//! filesystem/network/hostname view (the namespaces that actually matter
//! for a usable shell) are unaffected.

use kiln_cli::container::{Container, Status};
use kiln_image::store::Store;
use nix::pty::openpty;
use nix::unistd::ForkResult;
use std::ffi::CString;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};

use kilnd_core::conn::Conn;
use kilnd_core::http::{Request, Response};

/// Shells this endpoint is willing to exec - an allowlist rather than
/// trusting `?shell=` directly, since it's a query string reaching all
/// the way into `execv` inside the container's own namespaces. No param
/// (Settings > Terminal's "auto-detected") tries `/bin/bash` first - see
/// the fallback to `/bin/sh` below for images that don't have it.
const ALLOWED_SHELLS: &[&str] = &["/bin/sh", "/bin/bash"];

pub fn handle(store: &Store, id: &str, req: &Request, stream: &mut Conn, reader: &mut BufReader<Conn>) -> io::Result<()> {
    let shell = req
        .query
        .get("shell")
        .map(String::as_str)
        .filter(|s| ALLOWED_SHELLS.contains(s))
        .unwrap_or("/bin/bash")
        .to_string();
    let Some(mut container) = Container::resolve(store, id) else {
        return Response::text(404, "no such container").write_to(stream);
    };
    container.refresh(store);
    if container.status != Status::Running {
        return Response::text(400, "container is not running").write_to(stream);
    }
    let pid = nix::unistd::Pid::from_raw(container.pid.expect("Running implies pid is set"));

    // Open the pty *before* joining the container's mount namespace.
    // `openpty` opens `/dev/ptmx` in whatever mount namespace is
    // currently active - the container's rootfs generally has no devpts
    // of its own, so doing this after `setns(mnt)` fails with ENOENT.
    // Once open, the resulting fds stay valid across a later namespace
    // switch (open file descriptors aren't affected by which mount
    // namespace subsequently resolves new paths), so opening early and
    // carrying the fds along works fine.
    let pty = match openpty(None, None) {
        Ok(p) => p,
        Err(e) => return Response::text(500, format!("openpty: {e}")).write_to(stream),
    };

    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            drop(pty.master);
            let _ = nix::unistd::setsid();

            // Single-threaded from here on (fork() only ever duplicates
            // the calling thread), so - unlike the parent - this process
            // can join the container's user namespace at all, and gets a
            // private `fs_struct` for free for the `mnt` join too.
            if let Err(e) = kilnd_core::namespaces::join_namespaces(pid, &["user", "mnt", "uts", "ipc", "net"]) {
                eprintln!("kiln-exec: joining container namespaces: {e}");
                std::process::exit(1);
            }
            // Become "namespace uid/gid 0" for real, same as a freshly
            // created container does (see kiln-cli's run.rs). setgroups
            // must come first: our real supplementary groups (typically
            // just group 0, since kilnd runs as real root) survive the
            // setns and would otherwise make DAC checks use group
            // permission bits instead of "other" on container-root-owned
            // paths.
            if let Err(e) = nix::unistd::setgroups(&[]) {
                eprintln!("kiln-exec: setgroups: {e}");
                std::process::exit(1);
            }
            if let Err(e) = nix::unistd::setresgid(nix::unistd::Gid::from_raw(0), nix::unistd::Gid::from_raw(0), nix::unistd::Gid::from_raw(0)) {
                eprintln!("kiln-exec: setresgid: {e}");
                std::process::exit(1);
            }
            if let Err(e) = nix::unistd::setresuid(nix::unistd::Uid::from_raw(0), nix::unistd::Uid::from_raw(0), nix::unistd::Uid::from_raw(0)) {
                eprintln!("kiln-exec: setresuid: {e}");
                std::process::exit(1);
            }
            let _ = nix::unistd::chdir("/");

            let slave_fd = pty.slave.as_raw_fd();
            unsafe {
                libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0i32);
            }
            let _ = nix::unistd::dup2(slave_fd, 0);
            let _ = nix::unistd::dup2(slave_fd, 1);
            let _ = nix::unistd::dup2(slave_fd, 2);
            let shell_c = CString::new(shell.clone()).unwrap();
            let _ = nix::unistd::execv(&shell_c, &[shell_c.clone()]);
            // The requested shell doesn't exist in this image (execv only
            // returns on failure) - /bin/sh is the one shell every image
            // this project's tooling produces is guaranteed to have (it's
            // busybox's own entrypoint symlink in base:latest), so it's a
            // safe last resort rather than leaving the session dead.
            if shell != "/bin/sh" {
                let fallback = CString::new("/bin/sh").unwrap();
                let _ = nix::unistd::execv(&fallback, &[fallback.clone()]);
            }
            std::process::exit(127);
        }
        Ok(ForkResult::Parent { child }) => {
            drop(pty.slave);
            write!(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: kiln-exec\r\nConnection: Upgrade\r\n\r\n")?;
            stream.flush()?;
            shuttle(pty.master.as_raw_fd(), stream, reader, child)
        }
        Err(e) => Response::text(500, format!("fork: {e}")).write_to(stream),
    }
}

fn shuttle(
    master_fd: std::os::fd::RawFd,
    stream: &mut Conn,
    reader: &mut BufReader<Conn>,
    child: nix::unistd::Pid,
) -> io::Result<()> {
    // The pty master fd supports independent concurrent read/write from
    // different threads (it's a tty, not a regular file with a shared
    // seek position), so one dup'd handle per direction is all that's
    // needed - no locking between the two threads below.
    let dup_fd = nix::unistd::dup(master_fd).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    let mut pty_writer = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    let mut pty_reader = unsafe { std::fs::File::from_raw_fd(nix::unistd::dup(master_fd).map_err(|e| io::Error::from_raw_os_error(e as i32))?) };

    let mut client_writer = stream.try_clone()?;
    let reader_thread = std::thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = pty_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            client_writer.write_all(&buf[..n])?;
            client_writer.flush()?;
        }
        Ok(())
    });

    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if pty_writer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }

    let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGHUP);
    let _ = nix::sys::wait::waitpid(child, None);
    let _ = reader_thread.join();
    Ok(())
}
