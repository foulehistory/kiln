//! A default seccomp filter and a reduced capability set, applied to a
//! container's actual command right before it replaces Kiln's own init
//! code via `execve` (see `kiln-cli::commands::run::run_container_init`
//! and `kiln-image::build::run_step_init`, the two callers). Both are
//! narrowing steps only: they never widen anything the user namespace
//! (see `namespaces.rs`) and mount setup already established, and they
//! run *after* every mount/`pivot_root` operation Kiln's own init code
//! still needs to perform - dropping `CAP_SYS_ADMIN` or blocking `mount`
//! any earlier would break that setup itself.
//!
//! Applied unconditionally to every Kilfile `RUN` step (no per-step
//! escape hatch exists there - `Kilfile` has no per-instruction flag
//! syntax to hang one off today); `kiln run`/`kiln.yaml` services can opt
//! out explicitly via [`SecurityProfile`] - see its own docs.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::convert::TryInto;

/// Per-container overrides - absent/default means the full restricted
/// profile below applies, exactly as it always has. Every field is an
/// explicit *widening* a caller opts into; there is no way to end up more
/// restricted than the default by leaving these unset.
///
/// Persisted on `Container` (see `kiln-cli`) for the same restart-fidelity
/// reason as `volumes`/`env`/`secrets` there - so `kiln start` reapplies
/// the same profile instead of silently reverting to the stricter
/// default.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecurityProfile {
    /// `true` disables the seccomp filter entirely for this container -
    /// matches Docker's `--security-opt seccomp=unconfined` / Compose's
    /// `security_opt: [seccomp:unconfined]`. Capabilities are unaffected
    /// by this flag; use `cap_add` for that.
    #[serde(default)]
    pub seccomp_unconfined: bool,
    /// Extra capabilities to add on top of [`BASELINE_CAPABILITIES`],
    /// e.g. `["NET_ADMIN"]` or `["CAP_NET_ADMIN"]` (the `CAP_` prefix is
    /// optional, matching Docker's own `--cap-add` short form).
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// Capabilities to remove from the baseline, checked after `cap_add`
    /// (so `cap_add: [X], cap_drop: [X]` nets out to X being dropped, not
    /// a no-op - `cap_drop` always wins over `cap_add` for the same
    /// capability).
    #[serde(default)]
    pub cap_drop: Vec<String>,
}

/// The same 14 capabilities Docker grants by default - a well-known,
/// long-established "safe enough for ordinary containerized workloads"
/// baseline, not something this project is inventing from scratch.
/// Everything else (`CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`,
/// `CAP_SYS_MODULE`, ...) is dropped from the bounding set, which - for a
/// process that becomes uid 0 via `setresuid` the way every Kiln
/// container does - is what actually determines its capabilities after
/// `execve` (POSIX's "uid 0 gets its permitted set from the bounding
/// set" rule), not just an in-process bookkeeping detail.
pub const BASELINE_CAPABILITIES: &[caps::Capability] = &[
    caps::Capability::CAP_CHOWN,
    caps::Capability::CAP_DAC_OVERRIDE,
    caps::Capability::CAP_FOWNER,
    caps::Capability::CAP_FSETID,
    caps::Capability::CAP_KILL,
    caps::Capability::CAP_SETGID,
    caps::Capability::CAP_SETUID,
    caps::Capability::CAP_SETPCAP,
    caps::Capability::CAP_NET_BIND_SERVICE,
    caps::Capability::CAP_NET_RAW,
    caps::Capability::CAP_SYS_CHROOT,
    caps::Capability::CAP_MKNOD,
    caps::Capability::CAP_AUDIT_WRITE,
    caps::Capability::CAP_SETFCAP,
];

fn parse_capability(raw: &str) -> Result<caps::Capability> {
    let normalized = if raw.to_ascii_uppercase().starts_with("CAP_") {
        raw.to_ascii_uppercase()
    } else {
        format!("CAP_{}", raw.to_ascii_uppercase())
    };
    normalized
        .parse()
        .map_err(|_| Error::InvalidArgument(format!("unknown capability: {raw:?}")))
}

/// Resolves a [`SecurityProfile`] into the concrete set of capabilities
/// a container's bounding set will actually end up with:
/// [`BASELINE_CAPABILITIES`] plus `profile.cap_add`, minus
/// `profile.cap_drop` (drop always wins for a capability named in both -
/// see [`SecurityProfile`]'s own field docs). Shared by [`drop_capabilities`]
/// (which enforces this set) and [`apply_seccomp`] (which uses it to
/// decide which capability-gated syscalls in
/// [`conditionally_allowed_groups`] should also be seccomp-allowed - see
/// its own docs on why that matters), and by `kiln inspect --security`
/// for reporting what's actually in effect.
pub fn effective_capabilities(profile: &SecurityProfile) -> Result<std::collections::HashSet<caps::Capability>> {
    let mut allowed: std::collections::HashSet<caps::Capability> = BASELINE_CAPABILITIES.iter().copied().collect();
    for raw in &profile.cap_add {
        allowed.insert(parse_capability(raw)?);
    }
    for raw in &profile.cap_drop {
        allowed.remove(&parse_capability(raw)?);
    }
    Ok(allowed)
}

/// Drops every capability from the bounding set except
/// [`effective_capabilities`]. Must run after every mount/`pivot_root`
/// operation Kiln's own init code still needs `CAP_SYS_ADMIN` for (see
/// this module's own docs).
pub fn drop_capabilities(profile: &SecurityProfile) -> Result<()> {
    let allowed = effective_capabilities(profile)?;
    for cap in caps::all() {
        if !allowed.contains(&cap) {
            // Best-effort: a capability the kernel doesn't know about (an
            // older kernel than the `caps` crate's own enum) fails to
            // drop with ENOSYS/EINVAL rather than something worth
            // aborting container startup over - it was never grantable
            // in the first place on such a kernel.
            let _ = caps::drop(None, caps::CapSet::Bounding, cap);
        }
    }
    Ok(())
}

/// Reads `pid`'s real, kernel-reported capability bounding set from
/// `/proc/<pid>/status`'s `CapBnd:` line (a 64-bit hex bitmask - see
/// `capabilities(7)`) - independent, host-observed confirmation of what
/// [`drop_capabilities`] actually achieved for a specific running
/// process, as opposed to [`effective_capabilities`]'s computed
/// *intent*. Used by `kiln inspect --security` and its `kilnd` HTTP
/// equivalent to cross-check the two against each other, and by
/// `kiln-cli/tests/security_seccomp_caps.rs`'s own tests.
pub fn read_capability_bounding_set(pid: i32) -> Result<u64> {
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| Error::InvalidArgument(format!("reading /proc/{pid}/status: {e}")))?;
    let line = status
        .lines()
        .find(|l| l.starts_with("CapBnd:"))
        .ok_or_else(|| Error::InvalidArgument(format!("no CapBnd: line in /proc/{pid}/status")))?;
    let hex = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::InvalidArgument(format!("malformed CapBnd: line in /proc/{pid}/status: {line:?}")))?;
    u64::from_str_radix(hex, 16).map_err(|e| Error::InvalidArgument(format!("CapBnd: value {hex:?} isn't valid hex: {e}")))
}

/// Decodes a `CapBnd:`-shaped bitmask (see [`read_capability_bounding_set`])
/// into the concrete [`caps::Capability`] values it contains, using each
/// capability's own stable bit position (`Capability::bitmask`) - the
/// same kernel ABI numbers `capabilities(7)` documents.
pub fn decode_capability_set(mask: u64) -> Vec<caps::Capability> {
    caps::all().into_iter().filter(|c| mask & c.bitmask() != 0).collect()
}

/// Syscalls every container may always call, regardless of its granted
/// capabilities - ordinary file/socket/process/signal/timer operations
/// that carry no host-wide risk on their own (any real risk from these
/// is governed by the user-namespace/capability/mount-namespace layers
/// already in place, not by seccomp). Sourced directly from Docker's own
/// default seccomp profile's unconditional allow group (the ~300+
/// syscalls it permits with no capability requirement at all), filtered
/// to the syscalls that actually exist on this project's only supported
/// target (x86_64 Linux) - Docker's own list also includes 32-bit-compat
/// and other-arch syscalls (e.g. `mmap2`, `stat64`, `chown32`) that
/// simply don't exist as `libc::SYS_*` constants here and would never be
/// reachable on this target anyway.
///
/// Three syscalls in here are worth calling out explicitly since they
/// might look surprising next to [`conditionally_allowed_groups`]'s
/// capability-gated ones: `ptrace`, `process_vm_readv`, and
/// `process_vm_writev` are seccomp-allowed unconditionally (matching
/// Docker's own post-20.10 default), because seccomp isn't what actually
/// gates them - the kernel's own ptrace access checks (Yama, or plain
/// `CAP_SYS_PTRACE`) still require the caller to already be a relative
/// (parent/tracer of its own children) or hold `CAP_SYS_PTRACE`, which
/// isn't in [`BASELINE_CAPABILITIES`] - so an unprivileged container
/// gains nothing from this beyond debugging its own child processes,
/// exactly as it could without a container at all.
fn unconditionally_allowed_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_access,
        libc::SYS_adjtimex,
        libc::SYS_alarm,
        libc::SYS_arch_prctl,
        libc::SYS_bind,
        libc::SYS_brk,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_chdir,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_clock_adjtime,
        libc::SYS_clock_getres,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_connect,
        libc::SYS_copy_file_range,
        libc::SYS_creat,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_wait,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fadvise64,
        libc::SYS_fallocate,
        libc::SYS_fanotify_mark,
        libc::SYS_fchdir,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_fcntl,
        libc::SYS_fdatasync,
        libc::SYS_fgetxattr,
        libc::SYS_flistxattr,
        libc::SYS_flock,
        libc::SYS_fork,
        libc::SYS_fremovexattr,
        libc::SYS_fsetxattr,
        libc::SYS_fstat,
        libc::SYS_fstatfs,
        libc::SYS_fsync,
        libc::SYS_ftruncate,
        libc::SYS_futex,
        libc::SYS_futimesat,
        libc::SYS_get_robust_list,
        libc::SYS_getcpu,
        libc::SYS_getcwd,
        libc::SYS_getdents64,
        libc::SYS_getegid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getgroups,
        libc::SYS_getitimer,
        libc::SYS_getpeername,
        libc::SYS_getpgid,
        libc::SYS_getpgrp,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_getpriority,
        libc::SYS_getrandom,
        libc::SYS_getresgid,
        libc::SYS_getresuid,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_getsid,
        libc::SYS_getsockname,
        libc::SYS_getsockopt,
        libc::SYS_gettid,
        libc::SYS_gettimeofday,
        libc::SYS_getuid,
        libc::SYS_getxattr,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_init,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_rm_watch,
        libc::SYS_io_cancel,
        libc::SYS_io_destroy,
        libc::SYS_io_getevents,
        libc::SYS_io_setup,
        libc::SYS_io_submit,
        libc::SYS_ioctl,
        libc::SYS_ioprio_get,
        libc::SYS_ioprio_set,
        libc::SYS_kill,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_restrict_self,
        libc::SYS_lchown,
        libc::SYS_lgetxattr,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_listen,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_lremovexattr,
        libc::SYS_lseek,
        libc::SYS_lsetxattr,
        libc::SYS_lstat,
        libc::SYS_madvise,
        libc::SYS_membarrier,
        libc::SYS_memfd_create,
        libc::SYS_memfd_secret,
        libc::SYS_mincore,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_mknod,
        libc::SYS_mknodat,
        libc::SYS_mlock,
        libc::SYS_mlock2,
        libc::SYS_mlockall,
        libc::SYS_mmap,
        libc::SYS_modify_ldt,
        libc::SYS_mprotect,
        libc::SYS_mq_getsetattr,
        libc::SYS_mq_notify,
        libc::SYS_mq_open,
        libc::SYS_mq_timedreceive,
        libc::SYS_mq_timedsend,
        libc::SYS_mq_unlink,
        libc::SYS_mremap,
        libc::SYS_msgctl,
        libc::SYS_msgget,
        libc::SYS_msgrcv,
        libc::SYS_msgsnd,
        libc::SYS_msync,
        libc::SYS_munlock,
        libc::SYS_munlockall,
        libc::SYS_munmap,
        libc::SYS_name_to_handle_at,
        libc::SYS_nanosleep,
        libc::SYS_newfstatat,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_pause,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_send_signal,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_pkey_alloc,
        libc::SYS_pkey_free,
        libc::SYS_pkey_mprotect,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_prctl,
        libc::SYS_pread64,
        libc::SYS_preadv,
        libc::SYS_preadv2,
        libc::SYS_prlimit64,
        libc::SYS_process_mrelease,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pselect6,
        libc::SYS_ptrace,
        libc::SYS_pwrite64,
        libc::SYS_pwritev,
        libc::SYS_pwritev2,
        libc::SYS_read,
        libc::SYS_readahead,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_readv,
        libc::SYS_recvfrom,
        libc::SYS_recvmmsg,
        libc::SYS_recvmsg,
        libc::SYS_remap_file_pages,
        libc::SYS_removexattr,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_restart_syscall,
        libc::SYS_rmdir,
        libc::SYS_rseq,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_getattr,
        libc::SYS_sched_getparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_setattr,
        libc::SYS_sched_setparam,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_yield,
        libc::SYS_seccomp,
        libc::SYS_select,
        libc::SYS_semctl,
        libc::SYS_semget,
        libc::SYS_semop,
        libc::SYS_semtimedop,
        libc::SYS_sendfile,
        libc::SYS_sendmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendto,
        libc::SYS_set_robust_list,
        libc::SYS_set_tid_address,
        libc::SYS_setfsgid,
        libc::SYS_setfsuid,
        libc::SYS_setgid,
        libc::SYS_setgroups,
        libc::SYS_setitimer,
        libc::SYS_setpgid,
        libc::SYS_setpriority,
        libc::SYS_setregid,
        libc::SYS_setresgid,
        libc::SYS_setresuid,
        libc::SYS_setreuid,
        libc::SYS_setrlimit,
        libc::SYS_setsid,
        libc::SYS_setsockopt,
        libc::SYS_setuid,
        libc::SYS_setxattr,
        libc::SYS_shmat,
        libc::SYS_shmctl,
        libc::SYS_shmdt,
        libc::SYS_shmget,
        libc::SYS_shutdown,
        libc::SYS_sigaltstack,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_socketpair,
        libc::SYS_splice,
        libc::SYS_stat,
        libc::SYS_statfs,
        libc::SYS_statx,
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_sync,
        libc::SYS_sync_file_range,
        libc::SYS_syncfs,
        libc::SYS_sysinfo,
        libc::SYS_tee,
        libc::SYS_tgkill,
        libc::SYS_time,
        libc::SYS_timer_create,
        libc::SYS_timer_delete,
        libc::SYS_timer_getoverrun,
        libc::SYS_timer_gettime,
        libc::SYS_timer_settime,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_gettime,
        libc::SYS_timerfd_settime,
        libc::SYS_times,
        libc::SYS_tkill,
        libc::SYS_truncate,
        libc::SYS_umask,
        libc::SYS_uname,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_utime,
        libc::SYS_utimensat,
        libc::SYS_utimes,
        libc::SYS_vfork,
        libc::SYS_vmsplice,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_write,
        libc::SYS_writev,
    ]
}

/// Syscalls only allowed if the container's *effective* capability set
/// (baseline plus any `cap_add`, minus any `cap_drop` - see
/// [`effective_capabilities`]) includes at least one of the listed
/// capabilities - directly mirroring the capability-gated groups in
/// Docker's own default seccomp profile. Since [`BASELINE_CAPABILITIES`]
/// never includes any of these, none of this actually widens anything by
/// default; it only takes effect for a container that explicitly opted
/// into one of these capabilities via `--cap-add`/`cap_add:`, in which
/// case the matching syscalls become usable too - without this, adding
/// e.g. `CAP_SYS_PTRACE` would grant the capability but seccomp would
/// still block the syscalls that need it, silently defeating the
/// `--cap-add` escape hatch.
fn conditionally_allowed_groups() -> &'static [(&'static [caps::Capability], &'static [i64])] {
    &[
        (&[caps::Capability::CAP_DAC_READ_SEARCH], &[libc::SYS_open_by_handle_at]),
        (
            &[caps::Capability::CAP_SYS_ADMIN],
            &[
                libc::SYS_bpf,
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_fanotify_init,
                libc::SYS_lookup_dcookie,
                libc::SYS_mount,
                libc::SYS_move_mount,
                libc::SYS_open_tree,
                libc::SYS_perf_event_open,
                libc::SYS_quotactl,
                libc::SYS_setdomainname,
                libc::SYS_sethostname,
                libc::SYS_setns,
                libc::SYS_syslog,
                libc::SYS_umount2,
                libc::SYS_unshare,
            ],
        ),
        (&[caps::Capability::CAP_SYS_BOOT], &[libc::SYS_reboot]),
        (
            &[caps::Capability::CAP_SYS_MODULE],
            &[libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module],
        ),
        (&[caps::Capability::CAP_SYS_PACCT], &[libc::SYS_acct]),
        (&[caps::Capability::CAP_SYS_PTRACE], &[libc::SYS_kcmp, libc::SYS_pidfd_getfd]),
        (&[caps::Capability::CAP_SYS_RAWIO], &[libc::SYS_iopl, libc::SYS_ioperm]),
        (&[caps::Capability::CAP_SYS_TIME], &[libc::SYS_clock_settime, libc::SYS_settimeofday]),
        (&[caps::Capability::CAP_SYS_TTY_CONFIG], &[libc::SYS_vhangup]),
        (&[caps::Capability::CAP_SYS_NICE], &[libc::SYS_sched_setattr]),
        (&[caps::Capability::CAP_SYSLOG], &[libc::SYS_syslog]),
        (&[caps::Capability::CAP_BPF], &[libc::SYS_bpf]),
        (&[caps::Capability::CAP_PERFMON], &[libc::SYS_perf_event_open]),
    ]
}

/// `clone`'s flags argument (`arg[0]` on x86_64) must not request
/// creating any *new* namespace - `CLONE_NEWNS|CLONE_NEWCGROUP|
/// CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET` -
/// unless the container has `CAP_SYS_ADMIN` (handled unconditionally via
/// [`conditionally_allowed_groups`] instead). Ordinary thread/process
/// creation (`pthread_create`, `fork`-via-`clone`, ...) never sets any of
/// these bits, so this only blocks a container's own code from creating
/// namespaces Kiln itself already created for it from the host side
/// before seccomp was ever installed (see this module's own docs on
/// ordering) - directly mirroring Docker's own default profile's
/// identical restriction.
const CLONE_NEW_NAMESPACE_FLAGS_MASK: u64 = 0x7E020000;

/// Installs the default seccomp-bpf filter (no-op if
/// `profile.seccomp_unconfined`). A default-deny allow-list (see
/// [`unconditionally_allowed_syscalls`]/[`conditionally_allowed_groups`]
/// for what's actually in it and why) - anything not explicitly allowed
/// returns `EPERM` to the caller (matching Docker's own default
/// profile's choice - an error the calling program can usually detect
/// and handle, rather than `Trap`'s `SIGSYS`, which just kills it
/// outright). Must be the last thing this process does before `execve`:
/// once installed, the filter applies to every syscall this process (and
/// everything it execs into) makes from then on, including any of
/// Kiln's own remaining init code.
pub fn apply_seccomp(profile: &SecurityProfile) -> Result<()> {
    if profile.seccomp_unconfined {
        return Ok(());
    }

    let effective = effective_capabilities(profile)?;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for syscall in unconditionally_allowed_syscalls() {
        rules.insert(syscall, vec![]);
    }
    for (required_caps, syscalls) in conditionally_allowed_groups() {
        if required_caps.iter().any(|c| effective.contains(c)) {
            for &syscall in *syscalls {
                rules.insert(syscall, vec![]);
            }
        }
    }
    // `clone`/`clone3` already got an unconditional allow above if
    // CAP_SYS_ADMIN is in the effective set; otherwise, allow `clone`
    // restricted to not requesting any new namespace, rather than
    // leaving it out of the allow-list entirely - ordinary
    // threading/forking still needs it (see `CLONE_NEW_NAMESPACE_FLAGS_MASK`'s
    // own docs). `clone3` has no such fallback: it's CAP_SYS_ADMIN-only,
    // matching Docker's own default profile - its flags live in a struct
    // pointer argument, not a plain register, which seccomp can't
    // inspect the contents of the way it can `clone`'s.
    if let std::collections::btree_map::Entry::Vacant(entry) = rules.entry(libc::SYS_clone) {
        let condition = seccompiler::SeccompCondition::new(
            0,
            seccompiler::SeccompCmpArgLen::Qword,
            seccompiler::SeccompCmpOp::MaskedEq(CLONE_NEW_NAMESPACE_FLAGS_MASK),
            0,
        )
        .map_err(|e| Error::InvalidArgument(format!("building clone() seccomp condition: {e}")))?;
        let rule =
            seccompiler::SeccompRule::new(vec![condition]).map_err(|e| Error::InvalidArgument(format!("building clone() seccomp rule: {e}")))?;
        entry.insert(vec![rule]);
    }
    // `socket(domain, ...)`: allow every address family Docker's own
    // default profile does (essentially everything except a handful of
    // obscure/historical ones in the 38-40 range) - three alternative
    // conditions on the same argument, any one of which is enough.
    rules.insert(
        libc::SYS_socket,
        vec![
            seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                0,
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Lt,
                38,
            )
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp condition: {e}")))?])
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp rule: {e}")))?,
            seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                0,
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                39,
            )
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp condition: {e}")))?])
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp rule: {e}")))?,
            seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                0,
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Gt,
                40,
            )
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp condition: {e}")))?])
            .map_err(|e| Error::InvalidArgument(format!("building socket() seccomp rule: {e}")))?,
        ],
    );
    // `personality(persona)`: the handful of legitimate values glibc and
    // common tools actually pass - 0 (PER_LINUX, the normal case), 8
    // (PER_LINUX32), the same two with ADDR_NO_RANDOMIZE set (some
    // debuggers/security tools disable ASLR this way), and `0xffffffff`
    // (the documented "query current personality without changing it"
    // sentinel glibc itself uses at startup).
    rules.insert(
        libc::SYS_personality,
        [0u64, 8, 0x00020000, 0x00020008, 0xffffffff]
            .into_iter()
            .map(|value| {
                seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                    0,
                    seccompiler::SeccompCmpArgLen::Dword,
                    seccompiler::SeccompCmpOp::Eq,
                    value,
                )
                .map_err(|e| Error::InvalidArgument(format!("building personality() seccomp condition: {e}")))?])
                .map_err(|e| Error::InvalidArgument(format!("building personality() seccomp rule: {e}")))
            })
            .collect::<Result<Vec<_>>>()?,
    );

    let arch: seccompiler::TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| Error::InvalidArgument(format!("unsupported seccomp arch: {}", std::env::consts::ARCH)))?;

    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Errno(libc::EPERM as u32),
        seccompiler::SeccompAction::Allow,
        arch,
    )
    .map_err(|e| Error::InvalidArgument(format!("building seccomp filter: {e}")))?;
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| Error::InvalidArgument(format!("compiling seccomp filter: {e}")))?;
    seccompiler::apply_filter(&program).map_err(|e| Error::InvalidArgument(format!("applying seccomp filter: {e}")))?;

    if !effective.contains(&caps::Capability::CAP_SYS_ADMIN) {
        apply_clone3_enosys_patch(arch)?;
    }
    Ok(())
}

/// A second, narrower filter stacked *on top of* the one just installed -
/// not a workaround, but how Docker's own default profile gets this
/// exactly right too (see its `clone3` rule's explicit `errnoRet: 38`,
/// i.e. `ENOSYS`, confirmed by fetching Docker's actual default seccomp
/// profile rather than guessing at it).
///
/// Without CAP_SYS_ADMIN, the main filter above has no rule for
/// `clone3` at all, so its `mismatch_action` (`EPERM`) would apply.
/// That's wrong: modern glibc's `pthread_create` tries `clone3` first
/// and only falls back to the legacy `clone` syscall (which the main
/// filter *does* allow, restricted to not requesting new namespaces) if
/// `clone3` fails with `ENOSYS` specifically - `EPERM` is treated as a
/// hard failure instead of "not implemented, fall back", so every
/// thread-creating program (this was caught by a real `mysqld`
/// regression test against this exact allow-list) would fail to start
/// entirely, with `EPERM`/errno 1 surfacing as a generic "can't create
/// thread" error.
///
/// Kernel seccomp filters stack: every attached filter is consulted for
/// each syscall, and for two filters both returning `SECCOMP_RET_ERRNO`
/// for the same syscall, the *most recently installed* filter's errno
/// value wins (see `Documentation/userspace-api/seccomp_filter.rst`).
/// Installing this filter *after* the main one is what makes its
/// `ENOSYS` win over the main filter's `EPERM` for `clone3` specifically,
/// while its own `mismatch_action` (`Allow`) never overrides the main
/// filter's stricter verdict for anything else - `Allow` is the lowest
/// precedence action there is.
fn apply_clone3_enosys_patch(arch: seccompiler::TargetArch) -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_clone3, vec![]);
    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|e| Error::InvalidArgument(format!("building clone3() seccomp patch filter: {e}")))?;
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| Error::InvalidArgument(format!("compiling clone3() seccomp patch filter: {e}")))?;
    seccompiler::apply_filter(&program).map_err(|e| Error::InvalidArgument(format!("applying clone3() seccomp patch filter: {e}")))
}
