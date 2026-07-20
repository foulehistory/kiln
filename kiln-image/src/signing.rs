//! Ed25519 image signing: local key management (`kiln key generate`) and
//! the sign/verify primitives `registry.rs`'s push/pull hook into.
//!
//! Keys live at `$HOME/.kiln/key/{ed25519,ed25519.pub}`, independent of
//! whichever `--store` is active for a given command - identity isn't a
//! per-store thing, unlike everything else `kiln` manages (contrast with
//! `KILN_REGISTRY_USER`/`PASS`, already global env vars for the same
//! reason). Same shape `ssh-keygen` uses for `~/.ssh/id_ed25519` -
//! deliberately familiar rather than inventing a new convention.
//!
//! Both keys are stored as hex - the same encoding every SHA-256 digest
//! in this workspace already uses, so a key "looks like" everything else
//! `kiln` prints rather than needing its own base64/PEM reader.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::io;
use std::path::PathBuf;

pub fn key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".kiln").join("key")
}

pub fn private_key_path() -> PathBuf {
    key_dir().join("ed25519")
}

pub fn public_key_path() -> PathBuf {
    key_dir().join("ed25519.pub")
}

/// Generates a new keypair and writes both files - private key
/// permissions locked down to `0600` immediately after writing, same as
/// `ssh-keygen`. Overwrites unconditionally; callers that want to protect
/// an existing key should check `private_key_path().exists()` first and
/// gate on their own `--force`.
pub fn generate_and_save() -> io::Result<()> {
    std::fs::create_dir_all(key_dir())?;
    let signing_key = SigningKey::generate(&mut OsRng);

    let priv_path = private_key_path();
    std::fs::write(&priv_path, hex::encode(signing_key.to_bytes()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::write(public_key_path(), hex::encode(signing_key.verifying_key().to_bytes()))?;
    Ok(())
}

/// `None` if no local key is configured - the common case for a puller
/// who never intends to push, and for Docker-Hub-only usage (which never
/// consults this at all).
pub fn load_signing_key() -> Option<SigningKey> {
    let hex_str = std::fs::read_to_string(private_key_path()).ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&arr))
}

pub fn load_public_key_hex() -> Option<String> {
    std::fs::read_to_string(public_key_path()).ok().map(|s| s.trim().to_string())
}

pub fn sign(key: &SigningKey, data: &[u8]) -> String {
    hex::encode(key.sign(data).to_bytes())
}

/// `Ok(())` if `signature_hex` is a valid ed25519 signature over `data`
/// by the holder of `public_key_hex`; `Err` with a human-readable reason
/// otherwise (bad hex, wrong length, or genuine verification failure -
/// callers don't need to distinguish, just refuse the pull either way).
pub fn verify(public_key_hex: &str, data: &[u8], signature_hex: &str) -> Result<(), String> {
    let pub_bytes: [u8; 32] =
        hex::decode(public_key_hex).map_err(|e| format!("invalid public key hex: {e}"))?
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes: [u8; 64] =
        hex::decode(signature_hex).map_err(|e| format!("invalid signature hex: {e}"))?
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(data, &signature).map_err(|e| format!("signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trips() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let sig = sign(&key, b"hello world");
        assert!(verify(&pubkey_hex, b"hello world", &sig).is_ok());
        assert!(verify(&pubkey_hex, b"tampered", &sig).is_err());
    }
}
