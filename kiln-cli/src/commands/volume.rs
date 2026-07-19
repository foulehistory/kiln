//! `kiln volume` - named, persistent host directories that outlive any
//! one container, attachable to `kiln run` via `-v <name>:<path>`.
//!
//! Kept deliberately simple: a volume is just a directory under
//! `<store>/volumes/<name>`, bind-mounted into a container's rootfs (see
//! `commands::run` and `kilnd_core::rootfs::bind_mount`). No drivers, no
//! remote volume plugins - just a directory Kiln manages the lifecycle of
//! independently of any container.

use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use std::path::PathBuf;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create { name: String },
    Ls,
    Rm { name: String },
    /// Remove every volume not referenced by any container's stored `-v` specs
    Prune,
    /// Write a volume's contents to a tar.gz file
    Export { name: String, output: PathBuf },
    /// Create a new volume from a tar.gz previously produced by `export`
    Import { name: String, input: PathBuf },
}

pub fn volumes_dir(store: &Store) -> PathBuf {
    store.root().join("volumes")
}

pub fn path(store: &Store, name: &str) -> PathBuf {
    volumes_dir(store).join(name)
}

/// Tars + gzips a volume's contents. Shared by `kiln volume export` and
/// kilnd's `GET /volumes/:name/export` (which just calls this and streams
/// the bytes back as a download instead of writing them to a file).
pub fn export_bytes(store: &Store, name: &str) -> CliResult<Vec<u8>> {
    let dir = path(store, name);
    if !dir.is_dir() {
        return Err(CliError::msg(format!("no such volume: {name}")));
    }
    let mut gz = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all(".", &dir)?;
        builder.into_inner()?.finish()?;
    }
    Ok(gz)
}

/// The inverse of [`export_bytes`]: creates a brand new volume `name` from
/// tar.gz bytes. Refuses to overwrite an existing volume - importing into
/// an existing name would silently merge two unrelated trees together,
/// which is never what "restore a backup" means.
pub fn import_bytes(store: &Store, name: &str, tar_gz: &[u8]) -> CliResult {
    let dir = path(store, name);
    if dir.exists() {
        return Err(CliError::msg(format!("volume already exists: {name}")));
    }
    std::fs::create_dir_all(&dir)?;
    let decoder = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(decoder);
    if let Err(e) = archive.unpack(&dir) {
        // Don't leave a half-extracted volume behind on failure.
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e.into());
    }
    Ok(())
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Create { name } => {
            std::fs::create_dir_all(path(store, &name))?;
            println!("{name}");
        }
        Command::Ls => {
            println!("{:<24}MOUNTPOINT", "VOLUME NAME");
            if let Ok(entries) = std::fs::read_dir(volumes_dir(store)) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    println!("{:<24}{}", name, entry.path().display());
                }
            }
        }
        Command::Rm { name } => {
            std::fs::remove_dir_all(path(store, &name))?;
            println!("{name}");
        }
        Command::Prune => {
            let referenced: std::collections::HashSet<String> = crate::container::Container::list(store)
                .iter()
                .flat_map(|c| c.volumes.iter())
                .filter_map(|v| v.split_once(':').map(|(name, _)| name.to_string()))
                .collect();
            let mut any = false;
            if let Ok(entries) = std::fs::read_dir(volumes_dir(store)) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !referenced.contains(&name) && std::fs::remove_dir_all(entry.path()).is_ok() {
                        println!("{name}");
                        any = true;
                    }
                }
            }
            if !any {
                println!("nothing to prune");
            }
        }
        Command::Export { name, output } => {
            let bytes = export_bytes(store, &name)?;
            std::fs::write(&output, &bytes)?;
            println!("{}", output.display());
        }
        Command::Import { name, input } => {
            let bytes = std::fs::read(&input)?;
            import_bytes(store, &name, &bytes)?;
            println!("{name}");
        }
    }
    Ok(())
}
