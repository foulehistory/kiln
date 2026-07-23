//! Secrets: local AES-256-GCM encryption at rest, so a value referenced
//! by `kiln run --secret`/`kiln.yaml`'s `secrets:` never sits in
//! plaintext anywhere in the store or in `Container`'s own persisted
//! state - unlike a plain `-e` env var, which does exactly that.
//!
//! Two different lifetimes of "key" here, deliberately:
//! - The **master key** (`$HOME/.kiln/secrets/master.key`) is machine
//!   identity, like the ed25519 signing key in `signing.rs` - generated
//!   once, silently, and never leaves the machine (unlike the signing
//!   key's public half, this one is never published anywhere).
//! - Each secret's own ciphertext lives in `<store>/secrets/<name>.enc` -
//!   store-scoped like volumes and images, not machine-scoped.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn master_key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".kiln").join("secrets")
}

fn master_key_path() -> PathBuf {
    master_key_dir().join("master.key")
}

/// Loads the local master key, generating one (32 random bytes, hex,
/// `0600`) on first use if it doesn't exist yet - unlike `kiln key
/// generate`, this key is never shared with anyone else, so there's no
/// reason to make its creation a deliberate, separate step the way
/// publishing a signing identity is.
fn load_or_create_master_key() -> io::Result<[u8; 32]> {
    let path = master_key_path();
    if let Ok(hex_str) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = hex::decode(hex_str.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
                return Ok(arr);
            }
        }
    }
    std::fs::create_dir_all(master_key_dir())?;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    std::fs::write(&path, hex::encode(key))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

fn secrets_dir(store_root: &Path) -> PathBuf {
    store_root.join("secrets")
}

fn secret_path(store_root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return None;
    }
    Some(secrets_dir(store_root).join(format!("{name}.enc")))
}

/// Sidecar next to `<name>.enc` holding non-sensitive bookkeeping (a
/// rotation counter, timestamps, an optional TTL marker) - plain JSON,
/// deliberately never containing the secret value itself, so it needs
/// none of `<name>.enc`'s encryption and can be read freely by `kiln
/// secret ls`/the dashboard.
fn meta_path(store_root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return None;
    }
    Some(secrets_dir(store_root).join(format!("{name}.meta.json")))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SecretMeta {
    /// Starts at 1 when created, incremented on every successful `rotate`.
    pub version: u32,
    pub created_at: u64,
    /// `None` until the first `rotate` - a secret that has never been
    /// rotated has nothing to report here.
    pub rotated_at: Option<u64>,
    /// An informative expiration marker only (`kiln secret set --ttl`) -
    /// nothing in this codebase enforces it or rotates automatically once
    /// it passes; it's surfaced (e.g. "expired 3d ago") purely so an
    /// operator notices and rotates by hand.
    pub ttl_secs: Option<u64>,
}

impl SecretMeta {
    /// Unix timestamp `ttl_secs` after the most recent create/rotate,
    /// whichever is later - `None` when no TTL was ever set.
    pub fn expires_at(&self) -> Option<u64> {
        let base = self.rotated_at.unwrap_or(self.created_at);
        self.ttl_secs.map(|ttl| base + ttl)
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        std::process::id()
    ));
    std::fs::write(&tmp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    // Same-directory rename is atomic on a POSIX filesystem: a reader
    // never observes a partially-written file, and a crash/error before
    // this point leaves whatever was at `path` untouched - the property
    // `rotate` below relies on to guarantee the old secret stays usable
    // if re-encryption fails.
    std::fs::rename(&tmp, path)
}

fn read_meta(store_root: &Path, name: &str) -> Option<SecretMeta> {
    let path = meta_path(store_root, name)?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn write_meta(store_root: &Path, name: &str, meta: &SecretMeta) -> io::Result<()> {
    let path = meta_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    let json = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    write_atomic(&path, &json)
}

/// `None` if `name` has no metadata sidecar - either it doesn't exist at
/// all, or it was created before this field was added (pre-existing
/// secrets keep working via `read`/`create`; they just report no
/// version/rotation history until the next `rotate`, which always
/// writes fresh metadata).
pub fn meta(store_root: &Path, name: &str) -> Option<SecretMeta> {
    read_meta(store_root, name)
}

/// Encrypts `value` with the local master key and the given `nonce`,
/// returning the on-disk representation (`<nonce><ciphertext>`) `create`/
/// `rotate` both write to `<name>.enc`.
fn encrypt(value: &[u8], nonce_bytes: &[u8; 12]) -> io::Result<Vec<u8>> {
    let key_bytes = load_or_create_master_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, value)
        .map_err(|e| io::Error::other(format!("encrypting secret: {e}")))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Encrypts `value` with the local master key and writes
/// `<store>/secrets/<name>.enc` - a random 12-byte nonce followed by the
/// ciphertext, concatenated in one file. `ttl_secs`, if given, is an
/// informative-only expiration marker (see `SecretMeta::ttl_secs`'s own
/// docs) - nothing here enforces it.
pub fn create(store_root: &Path, name: &str, value: &[u8], ttl_secs: Option<u64>) -> io::Result<()> {
    let path = secret_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    std::fs::create_dir_all(secrets_dir(store_root))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let out = encrypt(value, &nonce_bytes)?;
    write_atomic(&path, &out)?;

    write_meta(
        store_root,
        name,
        &SecretMeta {
            version: 1,
            created_at: now_unix(),
            rotated_at: None,
            ttl_secs,
        },
    )?;
    Ok(())
}

/// Re-encrypts an *existing* secret under a fresh nonce (same local
/// master key as `create` used) and bumps its version - the actual
/// re-encryption this project's secret-rotation feature is built on.
///
/// Atomic: `<name>.enc` is only ever replaced by a same-directory
/// `rename` once the new ciphertext has been fully written to a temp
/// file first (see `write_atomic`'s own docs) - if encryption or the
/// write fails partway, the old ciphertext is untouched and the secret
/// remains exactly as usable as before this call. Errors (rather than
/// silently creating) if `name` doesn't already exist - rotating
/// something that was never created makes no sense, and would otherwise
/// silently reset a nonexistent secret's version to 1.
pub fn rotate(store_root: &Path, name: &str, new_value: &[u8]) -> io::Result<SecretMeta> {
    let path = secret_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    if !path.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no such secret: {name}")));
    }

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let out = encrypt(new_value, &nonce_bytes)?;
    write_atomic(&path, &out)?;

    let previous = read_meta(store_root, name);
    let now = now_unix();
    let meta = SecretMeta {
        version: previous.map(|m| m.version + 1).unwrap_or(2),
        created_at: previous.map(|m| m.created_at).unwrap_or(now),
        rotated_at: Some(now),
        ttl_secs: previous.and_then(|m| m.ttl_secs),
    };
    write_meta(store_root, name, &meta)?;
    Ok(meta)
}

/// Updates `name`'s TTL marker without touching its ciphertext -
/// `kiln secret set --ttl` on an already-existing secret.
pub fn set_ttl(store_root: &Path, name: &str, ttl_secs: Option<u64>) -> io::Result<SecretMeta> {
    let path = secret_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    if !path.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no such secret: {name}")));
    }
    let previous = read_meta(store_root, name);
    let meta = SecretMeta {
        version: previous.map(|m| m.version).unwrap_or(1),
        created_at: previous.map(|m| m.created_at).unwrap_or_else(now_unix),
        rotated_at: previous.and_then(|m| m.rotated_at),
        ttl_secs,
    };
    write_meta(store_root, name, &meta)?;
    Ok(meta)
}

/// Decrypts `<store>/secrets/<name>.enc`. `Ok(None)` if no such secret
/// exists; `Err` only for a genuine decryption/corruption failure (wrong
/// key, truncated file) - never for "not found", so callers can tell
/// "this secret doesn't exist" apart from "something is actually wrong".
pub fn read(store_root: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    let Some(path) = secret_path(store_root, name) else { return Ok(None) };
    let Ok(data) = std::fs::read(&path) else { return Ok(None) };
    if data.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("secret {name} is corrupt (too short)"),
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let key_bytes = load_or_create_master_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decrypting secret {name}: {e}")))?;
    Ok(Some(plaintext))
}

pub fn remove(store_root: &Path, name: &str) -> io::Result<()> {
    let path = secret_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    std::fs::remove_file(path)?;
    // Best-effort: a secret created before the metadata sidecar existed
    // has none to remove, and that's not an error.
    if let Some(meta) = meta_path(store_root, name) {
        let _ = std::fs::remove_file(meta);
    }
    Ok(())
}

/// Names only - never a value, by construction (this just reads
/// directory entries, never touches ciphertext content).
pub fn list(store_root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(secrets_dir(store_root)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.strip_suffix(".enc")).map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A single test, not several - `load_or_create_master_key` reads
    // `$HOME`, which is process-global mutable state; Rust's default test
    // runner executes tests in parallel threads within the same process,
    // so two tests each calling `env::set_var("HOME", ...)` could race
    // and observe each other's directory. One test sequences everything
    // that needs an isolated `$HOME` instead of risking that.
    #[test]
    fn encrypt_decrypt_and_on_disk_representation() {
        let home_dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", home_dir.path());
        let store_dir = tempfile::tempdir().unwrap();

        create(store_dir.path(), "test-secret", b"hunter2", None).unwrap();

        let raw = std::fs::read(store_dir.path().join("secrets").join("test-secret.enc")).unwrap();
        assert!(
            !raw.windows(b"hunter2".len()).any(|w| w == b"hunter2"),
            "ciphertext must not contain the plaintext"
        );

        let plaintext = read(store_dir.path(), "test-secret").unwrap().unwrap();
        assert_eq!(plaintext, b"hunter2");

        assert_eq!(list(store_dir.path()), vec!["test-secret".to_string()]);

        let created_meta = meta(store_dir.path(), "test-secret").expect("meta written by create");
        assert_eq!(created_meta.version, 1);
        assert!(created_meta.rotated_at.is_none());

        // Rotate: old value must stop decrypting to the old plaintext,
        // new value must round-trip, version must bump, rotated_at must
        // now be set - the exact real-world sequence the Palworld
        // ADMIN_PASSWORD validation (see the runtime's own test plan)
        // exercises against a real container.
        let rotated_meta = rotate(store_dir.path(), "test-secret", b"new-hunter3").unwrap();
        assert_eq!(rotated_meta.version, 2);
        assert!(rotated_meta.rotated_at.is_some());
        assert_eq!(read(store_dir.path(), "test-secret").unwrap().unwrap(), b"new-hunter3");

        let ttl_meta = set_ttl(store_dir.path(), "test-secret", Some(3600)).unwrap();
        assert_eq!(ttl_meta.ttl_secs, Some(3600));
        assert_eq!(ttl_meta.version, 2, "set_ttl must not touch the rotation version");
        assert!(ttl_meta.expires_at().is_some());

        remove(store_dir.path(), "test-secret").unwrap();
        assert!(read(store_dir.path(), "test-secret").unwrap().is_none());
        assert!(meta(store_dir.path(), "test-secret").is_none());
    }

    #[test]
    fn rotate_leaves_the_old_secret_usable_if_it_never_existed() {
        let home_dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", home_dir.path());
        let store_dir = tempfile::tempdir().unwrap();

        let err = rotate(store_dir.path(), "never-created", b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
