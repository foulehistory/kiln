//! The content-addressed blob store: Kiln's on-disk answer to "don't store
//! the same file twice".
//!
//! Docker (and most container engines) deduplicate at the *layer* level: if
//! two images happen to produce byte-identical layers, the layer is stored
//! once. Kiln deduplicates one level deeper, at the *file* level (an idea
//! borrowed from Nix's store): every regular file's content is hashed
//! (SHA-256) and stored exactly once at `blobs/<hex[0:2]>/<hex>`, regardless
//! of which layer or which image references it. A base image's `libc.so`
//! and a completely unrelated image's `libc.so` that happen to be
//! byte-identical occupy one copy on disk, not two. [`crate::layer`] builds
//! layers on top of this by recording, per file, which blob it points to;
//! materializing a layer back into a real directory (to use as an overlayfs
//! `lowerdir`) hardlinks each entry from the blob store rather than copying,
//! so the on-disk cost of a layer already present via another image is
//! effectively zero.
//!
//! # Why content-addressing implies a write-once, verify-by-hash store
//!
//! Every blob's name *is* its SHA-256 hash. Writing the same content twice
//! produces the same path, so a second write is a no-op (after confirming
//! the existing content actually matches, which it always will barring disk
//! corruption or a hash collision). This also means blobs are naturally
//! immutable: nothing in this module ever opens a blob for writing after
//! its initial, atomic creation.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A per-process counter mixed into temp file names so concurrent writers
/// into the same store never collide, without pulling in a random-number
/// crate just for this.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_suffix() -> String {
    format!("{}-{}", std::process::id(), TMP_COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// A SHA-256 content hash, hex-encoded when displayed or serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn of_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Hash(hasher.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHash(s.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidHash(s.to_string()))?;
        Ok(Hash(arr))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `f.pad`, not `write_str`: pad respects width/alignment/fill
        // flags from the caller's format spec (e.g. `{id:<66}` in
        // `kiln-cli`'s table printing); `write_str` silently ignores them.
        f.pad(&self.to_hex())
    }
}

impl TryFrom<String> for Hash {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Hash::from_hex(&s)
    }
}

impl From<Hash> for String {
    fn from(h: Hash) -> String {
        h.to_hex()
    }
}

/// The store root on disk. Everything Kiln persists - blobs, layers, images,
/// tags - lives under here (conventionally `~/.kiln` for a rootless,
/// per-user install, but tests point it at a tempdir).
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["blobs", "layers", "images", "refs", "containers"] {
            fs::create_dir_all(root.join(sub)).map_err(Error::io(root.join(sub)))?;
        }
        Ok(Store { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn layers_dir(&self) -> PathBuf {
        self.root.join("layers")
    }

    pub fn images_dir(&self) -> PathBuf {
        self.root.join("images")
    }

    pub fn refs_dir(&self) -> PathBuf {
        self.root.join("refs")
    }

    /// Where `kiln-cli` persists container state and per-container
    /// writable layers. Not used by anything in this crate directly -
    /// kept here just so every consumer of a `Store` agrees on one path.
    pub fn containers_dir(&self) -> PathBuf {
        self.root.join("containers")
    }

    /// Point `name:tag` at `id`. Overwrites any previous tag of the same
    /// name - tags are mutable pointers (like a git branch), unlike the
    /// content-addressed objects they point at.
    pub fn tag(&self, name: &str, tag: &str, id: Hash) -> Result<()> {
        let dir = self.refs_dir().join(name);
        fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
        write_atomically(&dir.join(tag), id.to_hex().as_bytes())
    }

    pub fn resolve_tag(&self, name: &str, tag: &str) -> Result<Hash> {
        let path = self.refs_dir().join(name).join(tag);
        let content = fs::read_to_string(&path).map_err(Error::io(&path))?;
        Hash::from_hex(content.trim())
    }

    pub fn write_json<T: serde::Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::io(parent))?;
        }
        let json = serde_json::to_vec_pretty(value).map_err(Error::json(path))?;
        write_atomically(path, &json)
    }

    pub fn read_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let bytes = fs::read(path).map_err(Error::io(path))?;
        serde_json::from_slice(&bytes).map_err(Error::json(path))
    }

    fn blob_path(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        self.root.join("blobs").join(&hex[0..2]).join(&hex)
    }

    pub fn has_blob(&self, hash: &Hash) -> bool {
        self.blob_path(hash).is_file()
    }

    /// Store `data` verbatim, returning its content hash. A no-op (besides
    /// re-hashing) if a blob with that hash already exists.
    pub fn put_bytes(&self, data: &[u8]) -> Result<Hash> {
        let hash = Hash::of_bytes(data);
        let dest = self.blob_path(&hash);
        if dest.is_file() {
            return Ok(hash);
        }
        fs::create_dir_all(dest.parent().unwrap()).map_err(Error::io(&dest))?;
        write_atomically(&dest, data)?;
        Ok(hash)
    }

    /// Stream-copy `src` into the store, hashing as it goes so we never
    /// have to hold a whole (potentially huge) file in memory just to name
    /// it. Returns the resulting content hash.
    pub fn put_file(&self, src: &Path) -> Result<Hash> {
        let mut input = File::open(src).map_err(Error::io(src))?;
        self.put_reader(&mut input)
    }

    /// Like [`Store::put_file`], but from any [`Read`] source - used for
    /// pulling registry layers, where each file's content arrives as one
    /// entry in a streamed tar rather than as a path on disk.
    pub fn put_reader(&self, input: &mut impl Read) -> Result<Hash> {
        let tmp_path = self.root.join("blobs").join(format!(".tmp-{}", unique_suffix()));
        let mut tmp = File::create(&tmp_path).map_err(Error::io(&tmp_path))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = input.read(&mut buf).map_err(Error::io(&tmp_path))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            tmp.write_all(&buf[..n]).map_err(Error::io(&tmp_path))?;
        }
        drop(tmp);
        let hash = Hash(hasher.finalize().into());
        let dest = self.blob_path(&hash);
        if dest.is_file() {
            let _ = fs::remove_file(&tmp_path);
            return Ok(hash);
        }
        fs::create_dir_all(dest.parent().unwrap()).map_err(Error::io(&dest))?;
        fs::rename(&tmp_path, &dest).map_err(Error::io(&dest))?;
        Ok(hash)
    }

    /// Place the blob for `hash` at `dest` with the given `mode`/`uid`/`gid`.
    ///
    /// This is where file-level dedup meets per-file metadata, and the two
    /// are in genuine tension: hardlinking shares one *inode*, but
    /// mode/uid/gid are properties *of* an inode, not of a directory entry.
    /// If two unrelated files in two different images happen to have
    /// identical *content* but different ownership (say, both are an empty
    /// file, one belonging to `root:root 644` and the other to
    /// `www-data:www-data 600`), blindly hardlinking both and then
    /// `chmod`/`chown`-ing "the file" would silently corrupt the other
    /// hardlink's permissions too, since there is only one inode between
    /// them.
    ///
    /// So: the first placement of a given blob "claims" it, stamping the
    /// blob's own on-disk metadata with the requested mode/uid/gid, and is
    /// hardlinked normally. Any later placement of the *same* blob with
    /// *matching* metadata is safe to hardlink too (sharing an inode that
    /// already has the right metadata changes nothing). A later placement
    /// with *different* metadata cannot safely share that inode, so it
    /// falls back to a real copy instead, which gets its own independent
    /// metadata. Dedup is preserved whenever it's actually safe, and
    /// correctness is never sacrificed for it.
    pub fn place_blob(&self, hash: &Hash, dest: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let src = self.blob_path(hash);
        if !src.is_file() {
            return Err(Error::MissingBlob(*hash));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(Error::io(parent))?;
        }

        let meta = fs::metadata(&src).map_err(Error::io(&src))?;
        let current_mode = meta.permissions().mode() & 0o7777;
        let unclaimed = meta.nlink() <= 1;
        let matches = current_mode == mode && meta.uid() == uid && meta.gid() == gid;

        if unclaimed || matches {
            if !matches {
                self.stamp(&src, mode, uid, gid)?;
            }
            return hardlink_or_copy(&src, dest);
        }

        fs::copy(&src, dest).map_err(Error::io(dest))?;
        self.stamp(dest, mode, uid, gid)
    }

    fn stamp(&self, path: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Error::io(path))?;
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .map_err(Error::syscall("chown", path))?;
        Ok(())
    }

    pub fn open_blob(&self, hash: &Hash) -> Result<File> {
        let path = self.blob_path(hash);
        File::open(&path).map_err(Error::io(path))
    }
}

fn hardlink_or_copy(src: &Path, dest: &Path) -> Result<()> {
    match fs::hard_link(src, dest) {
        Ok(()) => Ok(()),
        // Hardlinking across filesystems (e.g. store on one mount,
        // destination on a tmpfs) isn't possible; fall back to a real copy
        // so materialization still works, just without the dedup-on-disk
        // benefit for that one file.
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(src, dest).map_err(Error::io(dest))?;
            Ok(())
        }
        Err(e) => Err(Error::io(dest)(e)),
    }
}

fn write_atomically(dest: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = dest.with_file_name(format!(
        "{}.tmp-{}",
        dest.file_name().unwrap().to_string_lossy(),
        unique_suffix()
    ));
    {
        let mut tmp = File::create(&tmp_path).map_err(Error::io(&tmp_path))?;
        tmp.write_all(data).map_err(Error::io(&tmp_path))?;
    }
    fs::rename(&tmp_path, dest).map_err(Error::io(dest))
}
