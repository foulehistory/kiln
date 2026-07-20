//! Verifies overlayfs layering + `pivot_root` end to end: a container
//! writes into what it thinks is a plain filesystem, and from the host we
//! confirm that write actually landed in the per-container upper layer
//! (copy-up), that the read-only lower layer was never touched, and that
//! `mount_proc` scopes `/proc` to the container's own PID namespace rather
//! than leaking every host process into it.

use kilnd_core::error::{Error, Result};
use kilnd_core::namespaces::{spawn_isolated, IdMap, Spawn};
use kilnd_core::rootfs::{make_mounts_private, mount_overlay, mount_proc, pivot_root_into, OverlaySpec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{pipe, read, Uid};
use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: mount(2)/pivot_root(2) require root (or a delegated userns) in this environment");
        return false;
    }
    true
}

fn io_err(path: impl Into<std::path::PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}

#[test]
fn container_writes_copy_up_without_touching_the_lower_layer() {
    if !require_root() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let lower = tmp.path().join("lower");
    let upper = tmp.path().join("upper");
    let work = tmp.path().join("work");
    let merged = tmp.path().join("merged");
    for d in [&lower, &upper, &work, &merged] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(lower.join("hello.txt"), "from-lower").unwrap();

    let spec = OverlaySpec {
        lower_dirs: vec![lower.clone()],
        upper_dir: upper.clone(),
        work_dir: work.clone(),
        merged_dir: merged.clone(),
    };

    let opts = Spawn {
        uid_map: vec![IdMap {
            container_id: 0,
            host_id: 0,
            count: 1,
        }],
        gid_map: vec![IdMap {
            container_id: 0,
            host_id: 0,
            count: 1,
        }],
        ..Spawn::default()
    };

    let (report_read, report_write) = pipe().expect("pipe");
    let report_write_fd = report_write.as_raw_fd();
    let merged_for_child = merged.clone();

    let run_child = move || -> Result<()> {
        make_mounts_private()?;
        mount_overlay(&spec)?;
        pivot_root_into(&merged_for_child)?;
        mount_proc(Path::new("/proc"))?;

        let before = fs::read_to_string("/hello.txt").map_err(io_err("/hello.txt"))?;
        if before != "from-lower" {
            return Err(Error::InvalidArgument(format!("expected lower content inside container, got {before:?}")));
        }

        fs::write("/hello.txt", "modified-by-container").map_err(io_err("/hello.txt"))?;
        fs::write("/new-file.txt", "created-in-container").map_err(io_err("/new-file.txt"))?;

        // With a fresh /proc bound to our own (otherwise-empty) PID
        // namespace, we must be the only process visible.
        let pid_dirs = fs::read_dir("/proc")
            .map_err(io_err("/proc"))?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
            .count();
        if pid_dirs != 1 {
            return Err(Error::InvalidArgument(format!("expected exactly 1 visible pid, saw {pid_dirs}")));
        }

        let fd = unsafe { BorrowedFd::borrow_raw(report_write_fd) };
        nix::unistd::write(fd, &[1u8]).ok();
        Ok(())
    };

    let child_pid = spawn_isolated(&opts, run_child).expect("spawn_isolated");
    drop(report_write);

    let mut buf = [0u8; 1];
    let n = read(report_read.as_raw_fd(), &mut buf).expect("read report");

    match waitpid(child_pid, None).expect("waitpid") {
        WaitStatus::Exited(_, 0) => {}
        other => panic!("container setup failed: {other:?}"),
    }
    assert_eq!(n, 1, "child should have reported success before exiting");

    // Host-side verification: the lower layer is untouched...
    assert_eq!(
        fs::read_to_string(lower.join("hello.txt")).unwrap(),
        "from-lower",
        "lower (read-only) layer must never be modified"
    );
    // ...and the container's writes landed in the upper (writable) layer.
    assert_eq!(fs::read_to_string(upper.join("hello.txt")).unwrap(), "modified-by-container");
    assert_eq!(fs::read_to_string(upper.join("new-file.txt")).unwrap(), "created-in-container");
}
