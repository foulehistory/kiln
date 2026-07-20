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
    normalized.parse().map_err(|_| Error::InvalidArgument(format!("unknown capability: {raw:?}")))
}

/// Drops every capability from the bounding set except
/// [`BASELINE_CAPABILITIES`] plus `profile.cap_add`, minus
/// `profile.cap_drop` - see [`SecurityProfile`]'s own field docs for how
/// those two combine. Must run after every mount/`pivot_root` operation
/// Kiln's own init code still needs `CAP_SYS_ADMIN` for for (see this
/// module's own docs).
pub fn drop_capabilities(profile: &SecurityProfile) -> Result<()> {
    let mut allowed: std::collections::HashSet<caps::Capability> = BASELINE_CAPABILITIES.iter().copied().collect();
    for raw in &profile.cap_add {
        allowed.insert(parse_capability(raw)?);
    }
    for raw in &profile.cap_drop {
        allowed.remove(&parse_capability(raw)?);
    }

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

/// Syscalls blocked by the default filter - deliberately a curated
/// deny-list of specific dangerous/rarely-needed syscalls (matching
/// SECURITY.md's own pre-existing description of the gap this closes),
/// not a full Docker-style allow-list of the ~300 syscalls a container
/// might legitimately need. A full allow-list is the more thorough
/// design and the natural next step, but enumerating one with real
/// confidence nothing legitimate breaks is substantially more work than
/// this pass took on - see SECURITY.md's own note on this trade-off.
fn denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_acct,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        libc::SYS_perf_event_open,
        libc::SYS_bpf,
        libc::SYS_clock_adjtime,
        libc::SYS_clock_settime,
        libc::SYS_settimeofday,
        libc::SYS_adjtimex,
        libc::SYS_open_by_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_quotactl,
        libc::SYS_syslog,
        libc::SYS_lookup_dcookie,
    ]
}

/// Installs the default seccomp-bpf filter (no-op if
/// `profile.seccomp_unconfined`). Every syscall not in
/// [`denied_syscalls`] is allowed; every one that is returns `EPERM` to
/// the caller (matching Docker's own default profile's choice - an
/// error the calling program can usually detect and handle, rather than
/// `Trap`'s `SIGSYS`, which just kills it outright). Must be the last
/// thing this process does before `execve`: once installed, the filter
/// applies to every syscall this process (and everything it execs into)
/// makes from then on, including any of Kiln's own remaining init code.
pub fn apply_seccomp(profile: &SecurityProfile) -> Result<()> {
    if profile.seccomp_unconfined {
        return Ok(());
    }

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for syscall in denied_syscalls() {
        rules.insert(syscall, vec![]);
    }

    let arch: seccompiler::TargetArch =
        std::env::consts::ARCH.try_into().map_err(|_| Error::InvalidArgument(format!("unsupported seccomp arch: {}", std::env::consts::ARCH)))?;

    let filter = seccompiler::SeccompFilter::new(rules, seccompiler::SeccompAction::Allow, seccompiler::SeccompAction::Errno(libc::EPERM as u32), arch)
        .map_err(|e| Error::InvalidArgument(format!("building seccomp filter: {e}")))?;
    let program: seccompiler::BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| Error::InvalidArgument(format!("compiling seccomp filter: {e}")))?;
    seccompiler::apply_filter(&program).map_err(|e| Error::InvalidArgument(format!("applying seccomp filter: {e}")))
}
