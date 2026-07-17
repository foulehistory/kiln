//! `kiln volume` - named, persistent host directories that outlive any
//! one container, attachable to `kiln run` via `-v <name>:<path>`.
//!
//! Kept deliberately simple: a volume is just a directory under
//! `<store>/volumes/<name>`, bind-mounted into a container's rootfs (see
//! `commands::run` and `kilnd_core::rootfs::bind_mount`). No drivers, no
//! remote volume plugins - just a directory Kiln manages the lifecycle of
//! independently of any container.

use crate::error::CliResult;
use kiln_image::store::Store;
use std::path::PathBuf;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create { name: String },
    Ls,
    Rm { name: String },
}

pub fn volumes_dir(store: &Store) -> PathBuf {
    store.root().join("volumes")
}

pub fn path(store: &Store, name: &str) -> PathBuf {
    volumes_dir(store).join(name)
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
    }
    Ok(())
}
