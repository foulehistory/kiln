//! `kiln-cli` as a library: the same container/build/network/volume
//! machinery the `kiln` binary exposes over a CLI, factored out so
//! `kiln-compose` can drive it programmatically instead of shelling out to
//! `kiln` and scraping its output.

pub mod cgroup;
pub mod commands;
pub mod container;
pub mod error;
pub mod healthcheck;
pub mod supervisor;

use std::path::PathBuf;

pub fn default_store() -> PathBuf {
    if let Ok(s) = std::env::var("KILN_STORE") {
        return PathBuf::from(s);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".kiln")
}
