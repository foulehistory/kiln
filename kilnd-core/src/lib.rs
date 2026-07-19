//! `kilnd-core`: low-level Linux container runtime primitives for Kiln.
//!
//! This crate has no binary and no CLI — it is the isolation engine that
//! `kiln-cli`, `kilnd`, and friends build on top of. See the module docs
//! for the specifics of each primitive:
//!
//! - [`namespaces`] — process isolation via `clone(2)` and `CLONE_NEW*`.
//! - [`cgroups`] — CPU/memory/IO/pids limits via cgroups v2.
//! - [`rootfs`] — overlayfs layering and `pivot_root`.
//! - [`network`] — bridge networking and container attachment.

pub mod cgroups;
pub mod error;
pub mod namespaces;
pub mod network;
pub mod rootfs;

pub use error::{Error, Result};
