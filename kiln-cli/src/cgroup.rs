//! Where every `kiln run` container's cgroup lives, and small helpers for
//! reading the live stats `kilnd`'s dashboard API exposes.
//!
//! `kiln run` applies no hard limits unless `--memory`/`--cpus` are given
//! (matching Docker's own unlimited-by-default behavior) - the point of
//! always creating a cgroup, even an unrestricted one, is that
//! `memory.current`/`cpu.stat` become readable immediately, which is what
//! live "CPU/RAM" dashboard views need.

use kilnd_core::cgroups::{ensure_delegated_root, CgroupV2, Limits};
use kilnd_core::Result;
use std::path::{Path, PathBuf};

const MOUNT_ROOT: &str = "/sys/fs/cgroup";

pub fn root_dir() -> Result<PathBuf> {
    ensure_delegated_root(Path::new(MOUNT_ROOT), "kiln")
}

pub fn create_for(container_id: &str, limits: &Limits) -> Result<CgroupV2> {
    let root = root_dir()?;
    CgroupV2::create(&root, container_id, limits)
}

pub fn open(container_id: &str) -> Option<PathBuf> {
    let dir = Path::new(MOUNT_ROOT).join("kiln").join(container_id);
    dir.is_dir().then_some(dir)
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Stats {
    pub memory_current_bytes: u64,
    pub cpu_usage_usec: u64,
    pub pids_current: u64,
    /// `None` when the container has no network attached (no veth to read).
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

/// Read a snapshot of the container's cgroup stats. Returns `None` if it
/// has no cgroup (e.g. removed already, or predates this feature).
pub fn stats(container_id: &str) -> Option<Stats> {
    let dir = open(container_id)?;
    let memory_current_bytes = std::fs::read_to_string(dir.join("memory.current")).ok()?.trim().parse().ok()?;
    let pids_current = std::fs::read_to_string(dir.join("pids.current")).ok()?.trim().parse().ok()?;
    let cpu_stat = std::fs::read_to_string(dir.join("cpu.stat")).ok()?;
    let cpu_usage_usec = cpu_stat
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let (rx_bytes, tx_bytes) = match kilnd_core::network::veth_stats(container_id) {
        Some((rx, tx)) => (Some(rx), Some(tx)),
        None => (None, None),
    };
    Some(Stats {
        memory_current_bytes,
        cpu_usage_usec,
        pids_current,
        rx_bytes,
        tx_bytes,
    })
}

/// Best-effort: a cgroup can only be removed once it has no member
/// processes, which may take a moment after killing one - failures here
/// are logged, not propagated, so callers (e.g. `kiln rm -f`) don't fail
/// the whole removal over a cgroup directory that'll get cleaned up by
/// the kernel shortly anyway once truly empty.
pub fn remove(container_id: &str) {
    if let Some(dir) = open(container_id) {
        if let Err(e) = std::fs::remove_dir(&dir) {
            eprintln!("kiln: removing cgroup for {container_id}: {e}");
        }
    }
}
