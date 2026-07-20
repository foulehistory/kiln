pub mod build;
pub mod cp;
pub mod exec;
pub mod gc;
pub mod image;
pub mod images;
pub mod inspect;
pub mod key;
pub mod logs;
pub mod network;
pub mod node;
pub mod ps;
pub mod pull;
pub mod push;
pub mod rm;
pub mod rmi;
pub mod run;
pub mod secret;
pub mod start;
pub mod stop;
pub mod top;
pub mod volume;

use kiln_image::store::Store;
use std::path::Path;

/// A permanently-empty directory used as the sole overlayfs `lowerdir`
/// when a container has no real layers at all (`FROM scratch` with
/// nothing added) - overlayfs requires at least one `lowerdir`.
pub fn empty_dir(store: &Store) -> kiln_image::Result<std::path::PathBuf> {
    let dir = store.root().join("empty");
    std::fs::create_dir_all(&dir).map_err(kiln_image::error::Error::io(&dir))?;
    Ok(dir)
}

pub fn chown(path: &Path, uid: u32, gid: u32) -> kilnd_core::Result<()> {
    nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| kilnd_core::Error::InvalidArgument(format!("chown {}: {e}", path.display())))
}
