//! Kiln's fixed subordinate UID/GID range for remapped containers.
//!
//! [`crate::layer`] stores file ownership as small, *container-relative*
//! numbers (0 for root, 33 for `www-data`, etc.) so that layers stay
//! portable and reproducible independent of any one host's configuration.
//! But the actual files backing a materialized layer live on disk as real
//! files with real (host) UIDs/GIDs, and container processes only see the
//! "right" owner (e.g. root-owned `/etc/shadow` genuinely appearing
//! root-owned inside the container) if the on-disk UID is a value their
//! *own* user namespace's `uid_map` actually translates back to that
//! container-relative number.
//!
//! Since layers (and their backing blobs, via the content-addressed store)
//! are meant to be shared across many images and container runs, Kiln uses
//! **one fixed, global** subordinate range for every container it creates,
//! rather than a different range per container. This mirrors Docker's
//! daemon-wide `--userns-remap` (a single remap range for everything), and
//! for the same reason: if each container got its own range, every shared
//! layer would need re-`chown`ing per container, destroying both the
//! dedup benefit and the sharing itself. `SUBORDINATE_UID_BASE` is that
//! fixed offset: on-disk, "container-relative uid 0" is always really
//! host uid `SUBORDINATE_UID_BASE`; every container's own `uid_map` maps
//! its namespace's `0..SUBORDINATE_RANGE` to exactly that same host range,
//! so any container can correctly read any layer's ownership.
//!
//! (100000 is not arbitrary: it's the conventional start of the first
//! subordinate ID block `useradd`/`adduser` hand out via `/etc/subuid` on
//! most distributions, so it's unlikely to collide with real host accounts.)

use kilnd_core::namespaces::IdMap;

pub const SUBORDINATE_UID_BASE: u32 = 100_000;
pub const SUBORDINATE_GID_BASE: u32 = 100_000;
pub const SUBORDINATE_RANGE: u32 = 65_536;

/// The `uid_map`/`gid_map` every Kiln-managed container (build steps
/// included) is created with.
pub fn container_id_map(base: u32) -> Vec<IdMap> {
    vec![IdMap {
        container_id: 0,
        host_id: base,
        count: SUBORDINATE_RANGE,
    }]
}

/// Convert a real on-disk (host) UID/GID, as seen by a process outside any
/// container's user namespace, to the container-relative number Kiln
/// stores in a [`crate::layer::Entry`]. Falls back to returning the raw
/// host id unchanged if it falls outside Kiln's subordinate range - this
/// happens for files that were never touched by a Kiln-managed container
/// (e.g. present in a build context copied in as some other host user);
/// it's a best-effort fallback, not a silent corruption, and is documented
/// here rather than papered over.
pub fn host_to_container(host_id: u32, base: u32) -> u32 {
    if host_id >= base && host_id < base + SUBORDINATE_RANGE {
        host_id - base
    } else {
        host_id
    }
}

/// The inverse of [`host_to_container`]: where a container-relative id
/// from a stored layer should actually be `chown`ed to on disk when
/// materializing that layer for use as a real overlayfs `lowerdir`.
pub fn container_to_host(container_id: u32, base: u32) -> u32 {
    if container_id < SUBORDINATE_RANGE {
        base + container_id
    } else {
        container_id
    }
}
