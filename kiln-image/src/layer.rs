//! Layers: a content-addressed, ordered list of filesystem entries.
//!
//! A [`LayerManifest`] is deliberately *not* a tarball (unlike OCI layers).
//! It's a small JSON document listing every path the layer touches, each
//! pointing at a blob hash in [`crate::store`] rather than embedding file
//! content directly. This is what makes file-level dedup possible: the
//! manifest is cheap to store and diff, and the actual bytes live once in
//! the shared blob store no matter how many layers/images reference them.
//!
//! Two operations connect a layer to a real filesystem:
//!
//! - [`snapshot_dir`] walks a real directory (a container's overlayfs
//!   `upperdir` after a build step ran) and turns it into a
//!   `LayerManifest`, hashing every regular file into the store as it
//!   goes.
//! - [`materialize`] does the reverse: given a `LayerManifest`, populate a
//!   real directory suitable for use as an overlayfs `lowerdir`, hardlinking
//!   file content back out of the store wherever safe (see
//!   [`crate::store::Store::place_blob`] for when it isn't).
//!
//! # Reproducibility by omission
//!
//! [`Entry`] deliberately has no `mtime` field. Docker images are notorious
//! for being bit-*un*reproducible partly because layer tars embed
//! timestamps (file mtimes, tar header times) that differ build to build
//! even when the actual content doesn't. Kiln just never records that
//! information in the first place, so there's nothing non-deterministic to
//! accidentally leak into a layer's hash. `mode`/`uid`/`gid` *are*
//! recorded, deliberately: they affect real program behavior (setuid
//! binaries, service-account-owned files) and are as deterministic as the
//! build step that produced them.
//!
//! # Overlayfs whiteouts, preserved natively
//!
//! When a `RUN` step deletes a file that existed in a lower layer,
//! overlayfs itself records that deletion in the upperdir as a character
//! device special file with major/minor `0,0` at that path (and, for
//! deleting an entire directory's worth of lower content at once, an
//! `opaque` extended attribute on the replacement directory). Kiln doesn't
//! invent its own whiteout convention - it just preserves these exact
//! kernel-native markers in the layer manifest ([`EntryKind::Whiteout`],
//! `Dir { opaque: true }`) and recreates them faithfully on materialize.
//! That means a materialized layer can be handed straight back to the
//! kernel as another overlayfs `lowerdir` in a future stack and the
//! whiteouts just work, with zero whiteout-resolution logic of our own.

use crate::error::{Error, Result};
use crate::identity;
use crate::store::{Hash, Store};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::unistd::{Gid, Uid};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum EntryKind {
    /// `opaque` mirrors overlayfs's `trusted.overlay.opaque` xattr: this
    /// directory entirely replaces whatever directory of the same path
    /// existed in lower layers, rather than merging with it.
    Dir { opaque: bool },
    File { blob: Hash, size: u64 },
    Symlink { target: String },
    /// An overlayfs-native whiteout: this path is deleted relative to
    /// whatever lower layers are stacked underneath.
    Whiteout,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    /// Slash-separated, relative to the layer root, no leading `/`.
    pub path: String,
    /// Permission bits only (`mode & 0o7777`), including setuid/setgid/sticky.
    pub mode: u32,
    /// Container-relative owner, e.g. 0 for root - *not* a raw host UID.
    /// See [`crate::identity`] for why.
    pub uid: u32,
    pub gid: u32,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LayerManifest {
    /// Always sorted by `path`, so that the same filesystem state hashes
    /// to the same [`LayerManifest::id`] regardless of directory walk
    /// order.
    pub entries: Vec<Entry>,
}

impl LayerManifest {
    /// The layer's content hash: canonical (field order is fixed by the
    /// struct definition, entries are pre-sorted) JSON, hashed. Two layers
    /// with identical entries always produce the same id, on any machine,
    /// regardless of when they were built.
    pub fn id(&self) -> Hash {
        let json = serde_json::to_vec(self).expect("LayerManifest serialization cannot fail");
        Hash::of_bytes(&json)
    }

    /// Persist this manifest to `store`, keyed by its own id. A no-op if a
    /// layer with that id (i.e. identical content) is already saved.
    pub fn save(&self, store: &Store) -> Result<Hash> {
        let id = self.id();
        let path = store.layers_dir().join(format!("{id}.json"));
        if !path.is_file() {
            store.write_json(&path, self)?;
        }
        Ok(id)
    }

    pub fn load(store: &Store, id: &Hash) -> Result<Self> {
        let path = store.layers_dir().join(format!("{id}.json"));
        if !path.is_file() {
            return Err(Error::LayerNotFound(*id));
        }
        store.read_json(&path)
    }
}

fn path_to_entry_string(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

const OPAQUE_XATTR: &[u8] = b"trusted.overlay.opaque\0";

fn get_opaque_xattr(path: &Path) -> Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("path has no interior NUL");
    let mut buf = [0u8; 8];
    let ret = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            OPAQUE_XATTR.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
            _ => Err(Error::io(path)(err)),
        };
    }
    Ok(ret > 0 && buf[0] == b'y')
}

fn set_opaque_xattr(path: &Path) -> Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes()).expect("path has no interior NUL");
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            OPAQUE_XATTR.as_ptr() as *const libc::c_char,
            b"y".as_ptr() as *const libc::c_void,
            1,
            0,
        )
    };
    if ret < 0 {
        return Err(Error::io(path)(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Walk `root` (typically a container's overlayfs `upperdir` right after a
/// build step finished running) and turn it into a [`LayerManifest`],
/// hashing every regular file's content into `store` along the way.
/// `uid_base`/`gid_base` must be the same subordinate range the container
/// that produced `root` was run with (see [`crate::identity`]), so that
/// on-disk ownership is correctly converted back to container-relative
/// numbers.
pub fn snapshot_dir(root: &Path, store: &Store, uid_base: u32, gid_base: u32) -> Result<LayerManifest> {
    let mut entries = Vec::new();

    for dirent in walkdir::WalkDir::new(root).min_depth(1).into_iter() {
        let dirent = dirent.map_err(|e| Error::Build(format!("walking {}: {e}", root.display())))?;
        let path = dirent.path();
        let rel = path.strip_prefix(root).expect("walkdir yields paths under root");
        let rel_str = path_to_entry_string(rel);

        let meta = fs::symlink_metadata(path).map_err(Error::io(path))?;
        let mode = meta.permissions().mode() & 0o7777;
        let uid = identity::host_to_container(meta.uid(), uid_base);
        let gid = identity::host_to_container(meta.gid(), gid_base);
        let file_type = meta.file_type();

        let kind = if file_type.is_symlink() {
            let target = fs::read_link(path).map_err(Error::io(path))?;
            EntryKind::Symlink {
                target: path_to_entry_string(&target),
            }
        } else if file_type.is_dir() {
            EntryKind::Dir {
                opaque: get_opaque_xattr(path)?,
            }
        } else if file_type.is_char_device() && meta.rdev() == 0 {
            // major 0, minor 0: overlayfs's own whiteout marker.
            EntryKind::Whiteout
        } else if file_type.is_file() {
            let blob = store.put_file(path)?;
            EntryKind::File {
                blob,
                size: meta.len(),
            }
        } else {
            return Err(Error::Build(format!(
                "unsupported file type at {}: {file_type:?} (only regular files, dirs, symlinks, and overlayfs whiteouts are supported)",
                path.display()
            )));
        };

        entries.push(Entry {
            path: rel_str,
            mode,
            uid,
            gid,
            kind,
        });
    }

    entries.sort();
    Ok(LayerManifest { entries })
}

/// Populate `dest` with a real filesystem tree matching `manifest`,
/// suitable for use as an overlayfs `lowerdir`. Regular files are placed
/// via [`Store::place_blob`] (hardlinked out of the store whenever safe).
pub fn materialize(manifest: &LayerManifest, store: &Store, dest: &Path, uid_base: u32, gid_base: u32) -> Result<()> {
    let host_root_uid = identity::container_to_host(0, uid_base);
    let host_root_gid = identity::container_to_host(0, gid_base);
    create_dir_all_owned(dest, host_root_uid, host_root_gid)?;

    for entry in &manifest.entries {
        let target = dest.join(&entry.path);
        if let Some(parent) = target.parent() {
            create_dir_all_owned(parent, host_root_uid, host_root_gid)?;
        }
        let host_uid = identity::container_to_host(entry.uid, uid_base);
        let host_gid = identity::container_to_host(entry.gid, gid_base);

        match &entry.kind {
            EntryKind::Dir { opaque } => {
                fs::create_dir_all(&target).map_err(Error::io(&target))?;
                fs::set_permissions(&target, fs::Permissions::from_mode(entry.mode))
                    .map_err(Error::io(&target))?;
                chown(&target, host_uid, host_gid)?;
                if *opaque {
                    set_opaque_xattr(&target)?;
                }
            }
            EntryKind::File { blob, .. } => {
                store.place_blob(blob, &target, entry.mode, host_uid, host_gid)?;
            }
            EntryKind::Symlink { target: link_target } => {
                std::os::unix::fs::symlink(link_target, &target).map_err(Error::io(&target))?;
            }
            EntryKind::Whiteout => {
                mknod(&target, SFlag::S_IFCHR, Mode::empty(), makedev(0, 0))
                    .map_err(Error::syscall("mknod(whiteout)", &target))?;
            }
        }
    }

    Ok(())
}

/// Materialize layer `id` into its standard, cached location under the
/// store (`layers/<id>/`), skipping the work entirely if it's already
/// been materialized there (tracked by a `.kiln-complete` marker written
/// only after a materialization fully succeeds, so a process killed
/// mid-materialization leaves no marker and gets redone next time rather
/// than being trusted as complete).
pub fn materialize_cached(store: &Store, id: &Hash, uid_base: u32, gid_base: u32) -> Result<std::path::PathBuf> {
    let dest = store.layers_dir().join(id.to_hex());
    let marker = dest.join(".kiln-complete");
    if marker.is_file() {
        return Ok(dest);
    }
    let manifest = LayerManifest::load(store, id)?;
    materialize(&manifest, store, &dest, uid_base, gid_base)?;
    fs::write(&marker, b"").map_err(Error::io(&marker))?;
    Ok(dest)
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    nix::unistd::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(Error::syscall("chown", path))
}

/// Like `fs::create_dir_all`, but every directory this call actually
/// creates (as opposed to ones that already existed) is chowned to
/// `uid:gid` and given mode 0755.
///
/// A manifest only lists paths a build step actually touched - a `COPY
/// warm.sh /app/warm.sh` produces exactly one entry (for `warm.sh`
/// itself), never one for the `/app` directory that has to exist to hold
/// it, the same way Docker doesn't emit one for an implied parent. Before
/// this helper, that gap meant such directories were created via a bare
/// `fs::create_dir_all` and left owned by whatever real uid ran the
/// materializing process (host root) instead of the container's mapped
/// root - invisible until a later container actually needed to modify
/// something under that directory, at which point overlayfs's copy-up had
/// to replicate a parent directory owned by a uid unmapped in the
/// container's own user namespace, and the kernel's `vfsuid_has_mapping`
/// check turned that into `EOVERFLOW` ("value too large for defined data
/// type") - a confusing error from something as simple as `chmod +x` on a
/// freshly `COPY`'d file.
fn create_dir_all_owned(path: &Path, uid: u32, gid: u32) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all_owned(parent, uid, gid)?;
    }
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(Error::io(path))?;
            chown(path, uid, gid)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::io(path)(e)),
    }
}
