//! `kiln-compose backup`/`restore`: a single archive capturing everything
//! needed to recreate a project's *state* elsewhere - its `kiln.yaml`, its
//! volumes' contents, and which secrets it needs - but deliberately never
//! secret values themselves (see [`Manifest::secrets`]).
//!
//! The archive is a plain (uncompressed) tar, not tar.gz: each volume
//! inside it is already a `.tar.gz` produced by
//! [`kiln_cli::commands::volume::export_bytes`], and re-compressing
//! already-compressed data would just burn CPU for no real size win.

use crate::compose::ComposeFile;
use kiln_cli::commands::volume;
use kiln_cli::error::{CliError, CliResult};
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    project: String,
    created_at: u64,
    kiln_version: String,
    compose_file_name: String,
    volumes: Vec<String>,
    /// Secret *names* referenced by this project's services - never their
    /// values. A secret's value only ever exists as ciphertext under this
    /// machine's master key (see `kiln_image::secrets`' module docs: it
    /// never leaves the machine) - bundling it into a portable archive
    /// would either be silently unrestorable elsewhere, or need a second,
    /// backup-specific encryption scheme. Simpler and safer: the backup
    /// records which secrets a restore needs, `kiln secret create` puts
    /// the values back by hand.
    secrets: Vec<String>,
}

pub fn backup(store: &Store, project: &str, compose_file: &Path, compose: &ComposeFile, output: Option<PathBuf>) -> CliResult {
    let compose_file_name = compose_file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "kiln.yaml".to_string());
    let compose_source = std::fs::read(compose_file).map_err(|e| CliError::msg(format!("reading {}: {e}", compose_file.display())))?;

    let volumes: Vec<String> = compose.volumes.keys().cloned().collect();
    let secrets: BTreeSet<String> = compose.services.values().flat_map(|s| s.secrets.iter().cloned()).collect();

    let manifest = Manifest {
        project: project.to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        kiln_version: env!("CARGO_PKG_VERSION").to_string(),
        compose_file_name,
        volumes: volumes.clone(),
        secrets: secrets.into_iter().collect(),
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest).expect("Manifest serialization cannot fail");

    let output = output.unwrap_or_else(|| PathBuf::from(format!("{project}-{}.kiln-backup.tar", manifest.created_at)));
    let file = std::fs::File::create(&output).map_err(|e| CliError::msg(format!("creating {}: {e}", output.display())))?;
    let mut builder = tar::Builder::new(file);

    append_bytes(&mut builder, "manifest.json", &manifest_json)?;
    append_bytes(&mut builder, &manifest.compose_file_name, &compose_source)?;
    for name in &volumes {
        let bytes = volume::export_bytes(store, name).map_err(|e| CliError::msg(format!("exporting volume {name}: {e}")))?;
        append_bytes(&mut builder, &format!("volumes/{name}.tar.gz"), &bytes)?;
    }
    builder
        .into_inner()
        .map_err(|e| CliError::msg(format!("writing {}: {e}", output.display())))?;

    println!("Backed up {} volume(s) to {}", volumes.len(), output.display());
    if !manifest.secrets.is_empty() {
        println!("Secret values are never included in a backup - recreate these after restore:");
        for s in &manifest.secrets {
            println!("  - {s}");
        }
    }
    Ok(())
}

fn append_bytes<W: std::io::Write>(builder: &mut tar::Builder<W>, path: &str, data: &[u8]) -> CliResult {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, path, data)
        .map_err(|e| CliError::msg(format!("writing {path} into archive: {e}")))
}

pub fn restore(store: &Store, archive_path: &Path, dest: Option<PathBuf>) -> CliResult {
    let dest = dest.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dest).map_err(|e| CliError::msg(format!("creating {}: {e}", dest.display())))?;

    let manifest = read_manifest(archive_path)?;
    let compose_dest = dest.join(&manifest.compose_file_name);
    if compose_dest.exists() {
        return Err(CliError::msg(format!(
            "{} already exists - move it aside before restoring",
            compose_dest.display()
        )));
    }

    let file = std::fs::File::open(archive_path).map_err(|e| CliError::msg(format!("opening {}: {e}", archive_path.display())))?;
    let mut archive = tar::Archive::new(file);
    let mut restored_volumes = Vec::new();
    for entry in archive
        .entries()
        .map_err(|e| CliError::msg(format!("reading {}: {e}", archive_path.display())))?
    {
        let mut entry = entry.map_err(|e| CliError::msg(format!("{e}")))?;
        let entry_path = entry.path().map_err(|e| CliError::msg(format!("{e}")))?.into_owned();
        let entry_path_str = entry_path.to_string_lossy().into_owned();

        if entry_path_str == manifest.compose_file_name {
            let mut data = Vec::new();
            std::io::copy(&mut entry, &mut data).map_err(|e| CliError::msg(format!("{e}")))?;
            std::fs::write(&compose_dest, &data).map_err(|e| CliError::msg(format!("writing {}: {e}", compose_dest.display())))?;
        } else if let Some(name) = entry_path_str.strip_prefix("volumes/").and_then(|s| s.strip_suffix(".tar.gz")) {
            let mut data = Vec::new();
            std::io::copy(&mut entry, &mut data).map_err(|e| CliError::msg(format!("{e}")))?;
            volume::import_bytes(store, name, &data).map_err(|e| CliError::msg(format!("restoring volume {name}: {e}")))?;
            restored_volumes.push(name.to_string());
        }
    }

    println!("Restored {} to {}", manifest.compose_file_name, compose_dest.display());
    for name in &restored_volumes {
        println!("  volume: {name}");
    }
    if !manifest.secrets.is_empty() {
        println!("Secrets referenced by this project (recreate before `kiln-compose up`):");
        for s in &manifest.secrets {
            println!("  - {s}  (kiln secret create {s})");
        }
    }
    Ok(())
}

fn read_manifest(archive_path: &Path) -> CliResult<Manifest> {
    let file = std::fs::File::open(archive_path).map_err(|e| CliError::msg(format!("opening {}: {e}", archive_path.display())))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive
        .entries()
        .map_err(|e| CliError::msg(format!("reading {}: {e}", archive_path.display())))?
    {
        let mut entry = entry.map_err(|e| CliError::msg(format!("{e}")))?;
        let path = entry.path().map_err(|e| CliError::msg(format!("{e}")))?.into_owned();
        if path.to_string_lossy() == "manifest.json" {
            let mut data = Vec::new();
            std::io::copy(&mut entry, &mut data).map_err(|e| CliError::msg(format!("{e}")))?;
            return serde_json::from_slice(&data).map_err(|e| CliError::msg(format!("parsing manifest.json: {e}")));
        }
    }
    Err(CliError::msg("not a kiln-compose backup archive: no manifest.json found".to_string()))
}
