//! Resource limits via cgroups v2 (the unified hierarchy).
//!
//! Kiln targets cgroups v2 exclusively — no v1 fallback. v1's per-controller
//! hierarchies (separate trees for `cpu`, `memory`, `blkio`, ...) are what
//! made Docker's own cgroup handling notoriously fiddly; v2's single unified
//! tree with explicit, opt-in controller delegation is simpler to reason
//! about and is what every current Linux distribution now boots with by
//! default.
//!
//! # The delegation model
//!
//! A cgroup directory only lets its *children* use a controller (e.g.
//! `cpu`) if that controller has been explicitly written to the parent's
//! `cgroup.subtree_control` file (`echo +cpu > .../cgroup.subtree_control`).
//! This must be done at every level from the real root (`/sys/fs/cgroup`)
//! down to the direct parent of the leaf cgroup that will actually hold
//! processes and limits — a controller enabled two levels up but not one
//! level up still isn't usable by the leaf. [`ensure_delegated_root`]
//! performs this two-level enablement once for Kiln's own subtree
//! (`/sys/fs/cgroup/kiln`); [`CgroupV2::create`] then creates one leaf
//! directory per container underneath it.
//!
//! # Rootless note
//!
//! Writing to `/sys/fs/cgroup/...` directly requires root (or, for a
//! rootless setup, a cgroup subtree *delegated* to the user by systemd —
//! typically via a `user@.service` with `Delegate=yes`, the mechanism
//! Podman also relies on). This module only implements the raw file
//! operations; obtaining a writable, delegated cgroup path as an
//! unprivileged user is a separate concern left to the caller.

use crate::error::{self, Result};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};

/// Controllers Kiln enables for every container: CPU time, memory, block/IO
/// bandwidth, and process count (a cheap fork-bomb guard).
pub const CONTROLLERS: &[&str] = &["cpu", "memory", "io", "pids"];

/// Resource limits for one container's cgroup. Any `None` field is written
/// as cgroups v2's literal `"max"`, meaning unlimited.
#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
    /// Maximum CPU time in microseconds allowed per `cpu_period_us` window.
    /// E.g. `cpu_max_us = Some(50_000)` with the default period of
    /// `100_000` caps usage at 50% of one CPU.
    pub cpu_max_us: Option<u64>,
    pub cpu_period_us: u64,
    pub memory_max_bytes: Option<u64>,
    /// Maximum swap usage in bytes. `memory.max` alone is *not* a hard
    /// cap: when a cgroup hits it, the kernel first tries reclaim, and
    /// anonymous pages that haven't been touched recently are prime
    /// reclaim/swap-out candidates — so a container can keep allocating
    /// well past `memory_max_bytes` by having its cold pages quietly
    /// swapped out, never triggering the OOM killer, as long as swap
    /// space is available. Setting `memory_swap_max_bytes = Some(0)`
    /// alongside `memory_max_bytes` removes that escape hatch: with
    /// nothing left to reclaim, the kernel has no choice but to invoke
    /// the OOM killer once the limit is exceeded, which is what most
    /// users actually expect "memory limit" to mean.
    pub memory_swap_max_bytes: Option<u64>,
    /// A *soft* threshold (`memory.high`): once crossed, the kernel
    /// throttles/reclaims the cgroup aggressively but does not invoke the
    /// OOM killer - a warning shot before `memory_max_bytes` (the hard
    /// cap) is actually hit. `None` writes cgroups v2's literal `"max"`
    /// (no soft threshold, matching the pre-existing default before this
    /// field was added).
    pub memory_high_bytes: Option<u64>,
    pub pids_max: Option<u64>,
}

fn write_file(path: &Path, contents: impl AsRef<str>) -> Result<()> {
    fs::write(path, contents.as_ref()).map_err(error::io(path))
}

fn read_file(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(error::io(path))
}

/// Enable `CONTROLLERS` in `subtree_control` of `dir`, so cgroups created
/// underneath `dir` are allowed to use them. Only enables controllers that
/// are actually present in `dir`'s own `cgroup.controllers` (a controller
/// missing there means an ancestor never delegated it to us, which is a
/// caller configuration error, not something to silently paper over).
fn enable_subtree_controllers(dir: &Path) -> Result<()> {
    let available = read_file(&dir.join("cgroup.controllers"))?;
    let available: Vec<&str> = available.split_whitespace().collect();

    let mut to_enable = String::new();
    for c in CONTROLLERS {
        if available.contains(c) {
            to_enable.push('+');
            to_enable.push_str(c);
            to_enable.push(' ');
        }
    }
    if to_enable.is_empty() {
        return Ok(());
    }

    // cgroup.subtree_control accepts multiple "+controller" tokens in one
    // write, applied atomically.
    write_file(&dir.join("cgroup.subtree_control"), to_enable.trim_end())
}

/// Ensure `<mount_root>/<name>` exists as a cgroup with `CONTROLLERS`
/// delegated to it from `mount_root`, and returns its path. Call this once
/// (idempotent) before creating per-container leaf cgroups under it with
/// [`CgroupV2::create`].
pub fn ensure_delegated_root(mount_root: &Path, name: &str) -> Result<PathBuf> {
    enable_subtree_controllers(mount_root)?;

    let dir = mount_root.join(name);
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(error::io(&dir)(e)),
    }
    enable_subtree_controllers(&dir)?;
    Ok(dir)
}

/// A single container's leaf cgroup: no children of its own, just limits
/// and a set of member processes.
pub struct CgroupV2 {
    dir: PathBuf,
}

impl CgroupV2 {
    /// Create `<parent>/<id>` and apply `limits` to it. `parent` must
    /// already have `CONTROLLERS` delegated to it (see
    /// [`ensure_delegated_root`]).
    ///
    /// Stopping a container (as opposed to removing it) deliberately
    /// leaves its cgroup behind - see `kilnd`'s `stop` handler - so that
    /// restarting under the same id has somewhere to reattach a fresh
    /// process's stats to. A leftover, now-empty cgroup directory from
    /// that previous run is exactly what `create` finds itself facing
    /// then; a plain `mkdir` would fail on it with `EEXIST` even though
    /// there's nothing wrong with removing and recreating an empty
    /// directory that no live process is using.
    pub fn create(parent: &Path, id: &str, limits: &Limits) -> Result<Self> {
        let dir = parent.join(id);
        if dir.is_dir() {
            fs::remove_dir(&dir).map_err(error::io(&dir))?;
        }
        fs::create_dir(&dir).map_err(error::io(&dir))?;
        let cgroup = CgroupV2 { dir };
        cgroup.apply_limits(limits)?;
        Ok(cgroup)
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Wraps an already-existing cgroup directory (e.g. one found via a
    /// caller's own `open`/lookup by container id) so its limits can be
    /// changed with `apply_limits` without recreating it - unlike
    /// `create`, this never touches the directory itself, so it's safe
    /// to call against a *running* container's cgroup to change its
    /// resource limits live.
    pub fn from_existing(dir: PathBuf) -> Self {
        CgroupV2 { dir }
    }

    pub fn apply_limits(&self, limits: &Limits) -> Result<()> {
        let period = if limits.cpu_period_us == 0 { 100_000 } else { limits.cpu_period_us };
        let cpu_max = match limits.cpu_max_us {
            Some(us) => format!("{us} {period}"),
            None => format!("max {period}"),
        };
        write_file(&self.dir.join("cpu.max"), cpu_max)?;

        let mem_max = match limits.memory_max_bytes {
            Some(b) => b.to_string(),
            None => "max".to_string(),
        };
        write_file(&self.dir.join("memory.max"), mem_max)?;

        let mem_high = match limits.memory_high_bytes {
            Some(b) => b.to_string(),
            None => "max".to_string(),
        };
        write_file(&self.dir.join("memory.high"), mem_high)?;

        if let Some(b) = limits.memory_swap_max_bytes {
            write_file(&self.dir.join("memory.swap.max"), b.to_string())?;
        }

        let pids_max = match limits.pids_max {
            Some(n) => n.to_string(),
            None => "max".to_string(),
        };
        write_file(&self.dir.join("pids.max"), pids_max)?;

        Ok(())
    }

    /// Set a per-device I/O bandwidth/IOPS limit. `device` is a
    /// `"<major>:<minor>"` block device identifier (see `lsblk -o
    /// MAJ:MIN`); `params` is one or more `key=value` pairs from
    /// `io.max`'s format, e.g. `"rbps=1048576 wbps=1048576"`.
    pub fn set_io_max(&self, device: &str, params: &str) -> Result<()> {
        write_file(&self.dir.join("io.max"), format!("{device} {params}"))
    }

    /// Move `pid` into this cgroup. The kernel atomically removes it from
    /// whatever cgroup it was previously a member of.
    pub fn add_process(&self, pid: Pid) -> Result<()> {
        write_file(&self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// Current PIDs in this cgroup.
    pub fn processes(&self) -> Result<Vec<Pid>> {
        let contents = read_file(&self.dir.join("cgroup.procs"))?;
        Ok(contents.lines().filter_map(|l| l.trim().parse::<i32>().ok()).map(Pid::from_raw).collect())
    }

    pub fn memory_current(&self) -> Result<u64> {
        read_file(&self.dir.join("memory.current"))?
            .trim()
            .parse()
            .map_err(|_| error::Error::InvalidArgument("memory.current not a number".into()))
    }

    /// The cgroup's own `memory.events`'s `oom_kill` counter - how many
    /// times the kernel OOM killer has actually killed a process in this
    /// cgroup (distinct from `oom`, which counts OOM *conditions*
    /// regardless of whether a kill happened). This is the authoritative
    /// way to tell "the kernel killed this for exceeding `memory.max`"
    /// apart from any other reason a container's process might have died
    /// with `SIGKILL` (e.g. `kiln stop`'s own fallback, `kiln rm -f`) -
    /// same signal Docker/containerd use for their own `OOMKilled` status.
    /// Always starts at 0 for a freshly `create`d cgroup (never a
    /// leftover, reused directory - see `create`'s own docs), so any
    /// non-zero count here reflects *this* container's run.
    pub fn oom_kill_count(&self) -> Result<u64> {
        let events = read_file(&self.dir.join("memory.events"))?;
        Ok(events
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0))
    }

    /// Remove this cgroup. Fails with `EBUSY` if it still has member
    /// processes; callers must wait for the container to exit first.
    pub fn remove(self) -> Result<()> {
        fs::remove_dir(&self.dir).map_err(error::io(&self.dir))
    }
}
