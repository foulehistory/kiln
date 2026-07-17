//! Interactive, hands-on demo of the namespace primitives built in Phase 1.
//!
//! Run (as root, inside Linux/WSL2):
//!
//!     cargo run --example kiln-shell
//!
//! and you land in a real shell that is PID 1 of its own PID namespace,
//! has its own hostname, its own (down) network stack, and - by default -
//! sees itself as UID 0 while actually being an unprivileged UID on the
//! host. Things worth trying from inside:
//!
//!   hostname              # "kiln-demo", not the host's
//!   echo $$; ps aux       # you are PID 1, and the only process visible
//!   whoami; id            # uid=0 inside...
//!   ip addr                # ...but only a down loopback interface
//!
//! ...and from a *second* host terminal while the demo is running:
//!
//!   ps aux | grep kiln-shell     # shows the real, unprivileged host UID
//!   cat /proc/<pid>/status       # "Uid:" line confirms it
//!
//! There is no image format yet (that's Phase 2), so this reuses the
//! host's existing files directly rather than a proper overlayfs rootfs -
//! see rootfs.rs and its integration test for that full path, including
//! the copy-up behavior a real container gets. Pass `--as-real-root` to
//! skip the UID/GID remap if you'd rather have unrestricted access to
//! poke around with instead of hitting permission errors.

use kilnd_core::namespaces::{spawn_isolated, IdMap, Spawn};
use kilnd_core::rootfs::{make_mounts_private, mount_proc};
use kilnd_core::Error;
use nix::sys::wait::waitpid;
use nix::unistd::{Gid, Uid};
use std::ffi::CString;
use std::path::Path;

const REMAPPED_HOST_ID: u32 = 100_000;

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("kiln-shell: must run as root (writes uid/gid maps and calls mount(2))");
        std::process::exit(1);
    }

    let as_real_root = std::env::args().any(|a| a == "--as-real-root");
    let host_id = if as_real_root { 0 } else { REMAPPED_HOST_ID };
    let count = if as_real_root { 1 } else { 65_536 };

    let opts = Spawn {
        uid_map: vec![IdMap {
            container_id: 0,
            host_id,
            count,
        }],
        gid_map: vec![IdMap {
            container_id: 0,
            host_id,
            count,
        }],
        hostname: Some("kiln-demo".to_string()),
        ..Spawn::default()
    };

    println!(
        "kiln-shell: spawning a {} shell in new PID/MNT/UTS/IPC/NET/USER namespaces...\n",
        if as_real_root {
            "real-root"
        } else {
            "uid-remapped (container root = unprivileged host uid)"
        }
    );

    let child = spawn_isolated(&opts, move || {
        // Become "namespace uid/gid 0" for real, per the map above - see
        // namespaces.rs's module docs for why this explicit step is
        // required even after the map has been written. setgroups must
        // come first: clone() never touches supplementary groups, so
        // without clearing them the child keeps its parent's real gid 0,
        // which makes the kernel's DAC check use group permission bits
        // instead of "other" on any inode owned by group 0 (e.g. /root).
        nix::unistd::setgroups(&[]).map_err(|e| Error::InvalidArgument(format!("setgroups: {e}")))?;
        nix::unistd::setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))
            .map_err(|e| Error::InvalidArgument(format!("setresgid: {e}")))?;
        nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
            .map_err(|e| Error::InvalidArgument(format!("setresuid: {e}")))?;

        make_mounts_private()?;
        // A fresh /proc, scoped to our new PID namespace, shadowing the
        // host's - without this `ps`/`ls /proc` inside would still list
        // every host process.
        mount_proc(Path::new("/proc"))?;

        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        let shell_c = CString::new(shell).map_err(|e| Error::InvalidArgument(e.to_string()))?;
        nix::unistd::execvp(&shell_c, &[shell_c.clone()])
            .map_err(|e| Error::InvalidArgument(format!("execvp: {e}")))?;
        unreachable!("execvp only returns on error, which is handled above");
    })
    .expect("spawn_isolated");

    let status = waitpid(child, None);
    println!("\nkiln-shell: container exited: {status:?}");
}
