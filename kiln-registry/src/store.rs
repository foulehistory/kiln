//! On-disk layout for `kiln-registry`: plain files, no database engine -
//! same philosophy as `kiln-image`'s `Store`, `NetworkConfig`, and
//! volumes elsewhere in this workspace.
//!
//! ```text
//! <data-dir>/
//!   users.json                          # [{username, password_hash}]
//!   blobs/sha256/<hex>                  # content-addressed, shared across every repository
//!   manifests/<repository>/<tag>.json   # e.g. manifests/foulehistory/palworld/latest.json
//! ```

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
}

pub struct RegistryStore {
    data_dir: PathBuf,
}

impl RegistryStore {
    pub fn open(data_dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir.join("blobs").join("sha256"))?;
        std::fs::create_dir_all(data_dir.join("manifests"))?;
        Ok(RegistryStore { data_dir })
    }

    fn users_path(&self) -> PathBuf {
        self.data_dir.join("users.json")
    }

    pub fn load_users(&self) -> Vec<User> {
        std::fs::read(self.users_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save_users(&self, users: &[User]) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(users).expect("serialization cannot fail");
        std::fs::write(self.users_path(), json)
    }

    pub fn find_user(&self, username: &str) -> Option<User> {
        self.load_users().into_iter().find(|u| u.username == username)
    }

    /// `digest` must be `sha256:<64 lowercase hex chars>` - the only
    /// digest algorithm Kiln itself ever produces. Validated before it
    /// ever touches the filesystem: this is the only thing standing
    /// between an attacker-controlled digest string and a path
    /// traversal, since there's no further sanitization once it's
    /// joined onto `data_dir`.
    pub fn blob_path(&self, digest: &str) -> Option<PathBuf> {
        let hex = digest.strip_prefix("sha256:")?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(self.data_dir.join("blobs").join("sha256").join(hex))
    }

    /// Sanitizes `repository` (a slash-separated OCI repo name, e.g.
    /// `foulehistory/palworld`) the same way `kilnd`'s
    /// `resolve_within_volume` sanitizes a volume-relative path: `.`/`..`
    /// components are rejected outright rather than merely normalized
    /// away, so there's no ambiguity about what path a given repository
    /// name resolves to.
    fn repo_dir(&self, repository: &str) -> Option<PathBuf> {
        let mut path = self.data_dir.join("manifests");
        for component in repository.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return None;
            }
            path.push(component);
        }
        Some(path)
    }

    /// Only tag-addressed manifests are stored - `kiln push` always
    /// writes by tag, and reading back by digest isn't needed for the
    /// tag-sharing workflow this server exists for (see the module docs
    /// on why this is a deliberately narrow OCI Distribution
    /// implementation, not a general-purpose one).
    pub fn manifest_path(&self, repository: &str, tag: &str) -> Option<PathBuf> {
        if tag.is_empty() || tag.contains('/') || tag.contains("..") {
            return None;
        }
        Some(self.repo_dir(repository)?.join(format!("{tag}.json")))
    }

    pub fn write_blob(&self, digest: &str, data: &[u8]) -> Option<io::Result<()>> {
        let path = self.blob_path(digest)?;
        Some((|| {
            std::fs::create_dir_all(path.parent().expect("blob_path always has blobs/sha256 as parent"))?;
            std::fs::write(&path, data)
        })())
    }

    pub fn write_manifest(&self, repository: &str, tag: &str, data: &[u8]) -> Option<io::Result<()>> {
        let path = self.manifest_path(repository, tag)?;
        Some((|| {
            std::fs::create_dir_all(path.parent().expect("manifest_path always has a manifests/... parent"))?;
            std::fs::write(&path, data)
        })())
    }

    pub fn blob_exists(&self, digest: &str) -> bool {
        self.blob_path(digest).is_some_and(|p| p.is_file())
    }
}

pub fn read_file(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}
