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
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create {
        name: String,
    },
    Ls,
    Rm {
        name: String,
    },
    /// Remove every volume not referenced by any container's stored `-v` specs
    Prune,
    /// Write a volume's contents to a tar.gz file
    Export {
        name: String,
        output: PathBuf,
    },
    /// Create a new volume from a tar.gz previously produced by `export`
    Import {
        name: String,
        input: PathBuf,
    },
    #[command(subcommand)]
    Snapshot(SnapshotCommand),
}

#[derive(clap::Subcommand, Debug)]
pub enum SnapshotCommand {
    /// Snapshot a volume's current contents - a plain timestamped tar.gz
    /// copy stored *outside* the volume itself (see `snapshots_dir`), not
    /// an atomic filesystem-level snapshot - see this module's own docs
    /// on exactly what that means.
    Create {
        volume: String,
        /// Keep only the N most recent snapshots of this volume,
        /// deleting older ones right after this one is created.
        #[arg(long)]
        keep: Option<usize>,
    },
    List {
        volume: String,
    },
    /// Replace a volume's current contents with a previous snapshot's -
    /// not a merge: anything in the volume now that isn't in the
    /// snapshot is gone afterward.
    Restore {
        volume: String,
        snapshot_id: String,
    },
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

pub fn snapshots_dir(store: &Store, volume: &str) -> PathBuf {
    // Deliberately *outside* `volumes/<name>` itself (see this module's
    // own docs) - a snapshot living inside the volume it snapshots would
    // get swept up into every later snapshot of that same volume, and
    // would vanish along with the volume on `kiln volume rm`, defeating
    // the point of keeping restore points independent of the thing they
    // restore.
    store.root().join("volume-snapshots").join(volume)
}

pub struct SnapshotInfo {
    /// The unix timestamp (seconds) the snapshot was taken at, as a
    /// string - also its id, passed back to `restore`.
    pub id: String,
    pub size_bytes: u64,
}

/// Tars + gzips `volume`'s *current* contents, same as `export_bytes`,
/// into a new timestamped file under `snapshots_dir` - **not** an atomic
/// filesystem-level snapshot (no LVM/ZFS/btrfs copy-on-write underneath
/// this project on any platform it targets): if the volume's owning
/// container is actively writing to it while this runs, the tar can
/// legitimately contain a torn, part-old-part-new view of a file that
/// changed mid-copy. For a consistent snapshot of a volume still in use,
/// stop (or otherwise quiesce) whatever's writing to it first - this is
/// a plain copy, not a guarantee.
///
/// `keep`, if given, deletes the oldest snapshots of `volume` right
/// after this one is written, down to at most that many remaining.
pub fn snapshot_create(store: &Store, volume: &str, keep: Option<usize>) -> CliResult<SnapshotInfo> {
    let bytes = export_bytes(store, volume)?;
    let dir = snapshots_dir(store, volume);
    std::fs::create_dir_all(&dir)?;

    let mut id = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).to_string();
    // Two snapshots of the same volume within the same second (unlikely
    // by hand, easy in a test loop) would otherwise silently clobber
    // each other - append a disambiguating suffix instead.
    let mut suffix = 1u32;
    while dir.join(format!("{id}.tar.gz")).exists() {
        id = format!("{id}-{suffix}");
        suffix += 1;
    }

    let path = dir.join(format!("{id}.tar.gz"));
    std::fs::write(&path, &bytes)?;
    let size_bytes = bytes.len() as u64;

    if let Some(keep) = keep {
        let mut existing = list_snapshot_ids(store, volume);
        existing.sort();
        while existing.len() > keep {
            let oldest = existing.remove(0);
            let _ = std::fs::remove_file(snapshots_dir(store, volume).join(format!("{oldest}.tar.gz")));
        }
    }

    Ok(SnapshotInfo { id, size_bytes })
}

fn list_snapshot_ids(store: &Store, volume: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(snapshots_dir(store, volume)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.strip_suffix(".tar.gz")).map(str::to_string))
        .collect()
}

pub fn snapshot_list(store: &Store, volume: &str) -> Vec<SnapshotInfo> {
    let dir = snapshots_dir(store, volume);
    let mut ids = list_snapshot_ids(store, volume);
    ids.sort();
    ids.into_iter()
        .filter_map(|id| {
            let size_bytes = std::fs::metadata(dir.join(format!("{id}.tar.gz"))).ok()?.len();
            Some(SnapshotInfo { id, size_bytes })
        })
        .collect()
}

/// Replaces `volume`'s current contents with `snapshot_id`'s - a
/// restore, not a merge: every file/directory currently in the volume is
/// removed first, then the snapshot is extracted fresh, so nothing
/// written since the snapshot survives. See `snapshot_create`'s own docs
/// on why the snapshot being restored may itself already reflect a
/// mid-write tear, if it was taken while something was actively writing
/// to the volume - `restore` can't fix that after the fact, only put
/// back exactly what was captured.
pub fn snapshot_restore(store: &Store, volume: &str, snapshot_id: &str) -> CliResult {
    let snap_path = snapshots_dir(store, volume).join(format!("{snapshot_id}.tar.gz"));
    let bytes = std::fs::read(&snap_path).map_err(|_| CliError::msg(format!("no such snapshot: {snapshot_id}")))?;

    let dir = path(store, volume);
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p)?;
            } else {
                std::fs::remove_file(&p)?;
            }
        }
    } else {
        std::fs::create_dir_all(&dir)?;
    }

    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(&dir)?;
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
        Command::Snapshot(SnapshotCommand::Create { volume, keep }) => {
            let info = snapshot_create(store, &volume, keep)?;
            println!("{}", info.id);
        }
        Command::Snapshot(SnapshotCommand::List { volume }) => {
            println!("{:<16}SIZE", "SNAPSHOT ID");
            for s in snapshot_list(store, &volume) {
                println!("{:<16}{}", s.id, format_bytes(s.size_bytes));
            }
        }
        Command::Snapshot(SnapshotCommand::Restore { volume, snapshot_id }) => {
            snapshot_restore(store, &volume, &snapshot_id)?;
            println!("{volume} restored to snapshot {snapshot_id}");
        }
    }
    Ok(())
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}
