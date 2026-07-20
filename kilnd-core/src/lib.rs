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
//! - [`http`]/[`conn`] — the minimal hand-rolled HTTP/1.1 server layer
//!   shared by `kilnd` and `kiln-registry`, so a second server binary
//!   doesn't need to either depend on `kilnd` or duplicate request
//!   parsing.

pub mod cgroups;
pub mod conn;
pub mod error;
pub mod http;
pub mod namespaces;
pub mod netbpf;
pub mod network;
pub mod rootfs;
pub mod security;

pub use error::{Error, Result};
