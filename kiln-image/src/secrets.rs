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
use std::io;
use std::path::{Path, PathBuf};

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

/// Encrypts `value` with the local master key and writes
/// `<store>/secrets/<name>.enc` - a random 12-byte nonce followed by the
/// ciphertext, concatenated in one file.
pub fn create(store_root: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let path = secret_path(store_root, name).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret name"))?;
    std::fs::create_dir_all(secrets_dir(store_root))?;

    let key_bytes = load_or_create_master_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, value)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypting secret: {e}")))?;

    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    std::fs::write(&path, out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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
    std::fs::remove_file(path)
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

        create(store_dir.path(), "test-secret", b"hunter2").unwrap();

        let raw = std::fs::read(store_dir.path().join("secrets").join("test-secret.enc")).unwrap();
        assert!(
            !raw.windows(b"hunter2".len()).any(|w| w == b"hunter2"),
            "ciphertext must not contain the plaintext"
        );

        let plaintext = read(store_dir.path(), "test-secret").unwrap().unwrap();
        assert_eq!(plaintext, b"hunter2");

        assert_eq!(list(store_dir.path()), vec!["test-secret".to_string()]);

        remove(store_dir.path(), "test-secret").unwrap();
        assert!(read(store_dir.path(), "test-secret").unwrap().is_none());
    }
}
