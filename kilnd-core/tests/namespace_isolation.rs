//! Verifies that `spawn_isolated` actually isolates a real process: the
//! child must land in different PID/MNT/UTS/IPC/NET/USER namespaces than
//! the test process, must become PID 1 of its own PID namespace, and
//! (once it adopts its mapped identity) must appear as UID 0 inside while
//! remaining an unprivileged UID as seen from the host.

use kilnd_core::namespaces::{ns_id, spawn_isolated, IdMap, Namespaces, Spawn};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{pipe, read, Gid, Pid, Uid};
use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};

const NS_KINDS: &[&str] = &["pid", "mnt", "uts", "ipc", "net", "user"];
/// A host UID/GID far outside any real account, standing in for the kind
/// of dedicated subordinate ID range `/etc/subuid` would hand out.
const REMAPPED_HOST_ID: u32 = 100_000;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!(
            "skipping: writing a multi-entry, non-self uid/gid map requires \
             CAP_SETUID/CAP_SETGID in the host namespace (i.e. root)"
        );
        return false;
    }
    true
}

#[test]
fn child_is_isolated_and_uid_is_remapped() {
    if !require_root() {
        return;
    }

    let parent_pid = Pid::this();
    let parent_ns_ids: Vec<String> = NS_KINDS.iter().map(|k| ns_id(parent_pid, k).expect("read parent ns id")).collect();

    // Child reports {pid, uid, gid} it observes about itself, from inside
    // its own namespaces, back to us over a pipe.
    let (report_read, report_write) = pipe().expect("pipe");
    let report_write_fd = report_write.as_raw_fd();
    // A zombie process has already released its namespace references by
    // the time it's inspectable as a zombie - /proc/<pid>/ns/* and the
    // "real" uid in /proc/<pid>/status are only guaranteed available
    // while the process is genuinely still running. So after reporting,
    // the child blocks here until we're done inspecting it from the host
    // side, instead of exiting immediately.
    let (hold_read, hold_write) = pipe().expect("pipe");
    let hold_read_fd = hold_read.as_raw_fd();

    let opts = Spawn {
        uid_map: vec![IdMap {
            container_id: 0,
            host_id: REMAPPED_HOST_ID,
            count: 65_536,
        }],
        gid_map: vec![IdMap {
            container_id: 0,
            host_id: REMAPPED_HOST_ID,
            count: 65_536,
        }],
        hostname: Some("kiln-test".to_string()),
        ..Spawn::default()
    };

    let child_pid = spawn_isolated(&opts, move || {
        // Adopt the mapped identity. Only now does the process's *real*
        // (kernel) credential become REMAPPED_HOST_ID; getuid()/getgid()
        // afterward report 0 because that's how the namespace's own map
        // translates that real credential back for internal queries. See
        // namespaces.rs's module docs for the full explanation of why
        // this two-step (write map, then setresuid) dance is required.
        nix::unistd::setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)).expect("setresgid(0)");
        nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).expect("setresuid(0)");

        let pid = nix::unistd::getpid();
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();

        let mut report = Vec::with_capacity(12);
        report.extend_from_slice(&pid.as_raw().to_le_bytes());
        report.extend_from_slice(&uid.as_raw().to_le_bytes());
        report.extend_from_slice(&gid.as_raw().to_le_bytes());
        let fd = unsafe { BorrowedFd::borrow_raw(report_write_fd) };
        nix::unistd::write(fd, &report).expect("write report");

        let hold_fd = unsafe { BorrowedFd::borrow_raw(hold_read_fd) };
        let mut go = [0u8; 1];
        nix::unistd::read(hold_fd.as_raw_fd(), &mut go).expect("wait for hold release");
        Ok(())
    })
    .expect("spawn_isolated");

    // Parent's own copy of the write end must be closed or our read below
    // blocks forever waiting for a EOF that never comes.
    drop(report_write);

    let mut buf = [0u8; 12];
    let mut got = 0;
    while got < buf.len() {
        got += read(report_read.as_raw_fd(), &mut buf[got..]).expect("read report");
    }
    let reported_pid = i32::from_le_bytes(buf[0..4].try_into().unwrap());
    let reported_uid = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let reported_gid = u32::from_le_bytes(buf[8..12].try_into().unwrap());

    // The child is still alive and blocked on `hold_read` at this point,
    // so its namespace references and real credentials are still valid to
    // inspect from the host.
    let host_status = fs::read_to_string(format!("/proc/{child_pid}/status")).expect("read child status");
    let host_uid_line = host_status.lines().find(|l| l.starts_with("Uid:")).expect("Uid: line");
    let host_real_uid: u32 = host_uid_line.split_whitespace().nth(1).unwrap().parse().unwrap();

    // Every requested namespace must differ from the test process's own.
    let mut ns_mismatches = Vec::new();
    for (kind, parent_id) in NS_KINDS.iter().zip(parent_ns_ids.iter()) {
        let child_id = ns_id(child_pid, kind).expect("read child ns id");
        if &child_id == parent_id {
            ns_mismatches.push(*kind);
        }
    }

    nix::unistd::write(&hold_write, &[1u8]).expect("release child");
    drop(hold_write);

    match waitpid(child_pid, None).expect("waitpid") {
        WaitStatus::Exited(_, 0) => {}
        other => panic!("child did not exit cleanly: {other:?}"),
    }

    assert!(
        ns_mismatches.is_empty(),
        "namespaces shared with parent that should have been isolated: {ns_mismatches:?}"
    );

    // The child is PID 1 inside its own new PID namespace, regardless of
    // whatever large host PID `spawn_isolated` returned.
    assert_eq!(reported_pid, 1, "child should be PID 1 in its own namespace");

    // Inside the container it looks like root...
    assert_eq!(reported_uid, 0, "container should see itself as uid 0");
    assert_eq!(reported_gid, 0, "container should see itself as gid 0");

    // ...but the host sees an unprivileged, dedicated id - never literal
    // root. This is the actual security property user namespace remapping
    // buys.
    assert_eq!(host_real_uid, REMAPPED_HOST_ID, "host must see the remapped id, never uid 0");
    assert_ne!(host_real_uid, 0);
}

#[test]
fn namespaces_not_requested_are_left_shared() {
    if !require_root() {
        return;
    }

    let parent_pid = Pid::this();
    // Only isolate PID + mount; leave UTS/IPC/NET/USER shared with the host.
    let opts = Spawn {
        namespaces: Namespaces {
            pid: true,
            mount: true,
            uts: false,
            ipc: false,
            net: false,
            user: false,
        },
        ..Spawn::default()
    };

    let (done_read, done_write) = pipe().expect("pipe");
    let done_write_fd = done_write.as_raw_fd();
    // See the comment in child_is_isolated_and_uid_is_remapped: the child
    // must still be genuinely running, not a zombie, when we inspect its
    // /proc/<pid>/ns/* entries.
    let (hold_read, hold_write) = pipe().expect("pipe");
    let hold_read_fd = hold_read.as_raw_fd();

    let child_pid = spawn_isolated(&opts, move || {
        let fd = unsafe { BorrowedFd::borrow_raw(done_write_fd) };
        nix::unistd::write(fd, &[1u8]).expect("signal done");

        let mut go = [0u8; 1];
        let hold_fd = unsafe { BorrowedFd::borrow_raw(hold_read_fd) };
        nix::unistd::read(hold_fd.as_raw_fd(), &mut go).expect("wait for hold release");
        Ok(())
    })
    .expect("spawn_isolated");
    drop(done_write);

    let mut buf = [0u8; 1];
    read(done_read.as_raw_fd(), &mut buf).expect("read done signal");

    for kind in ["uts", "ipc", "net", "user"] {
        assert_eq!(
            ns_id(child_pid, kind).unwrap(),
            ns_id(parent_pid, kind).unwrap(),
            "{kind} namespace should be shared when not requested"
        );
    }
    for kind in ["pid", "mnt"] {
        assert_ne!(
            ns_id(child_pid, kind).unwrap(),
            ns_id(parent_pid, kind).unwrap(),
            "{kind} namespace should be isolated"
        );
    }

    nix::unistd::write(&hold_write, &[1u8]).expect("release child");
    drop(hold_write);

    waitpid(child_pid, None).expect("waitpid");
}
