//! Real registry GC test: pushes real blobs and a real manifest that
//! only references some of them, confirms `--dry-run` reports the
//! orphan without touching it, then confirms a real run actually
//! deletes only the truly unreferenced blob - the referenced ones stay
//! on disk untouched.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Registry {
    child: Child,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_registry(data_dir: &Path, port: u16) -> Registry {
    let child = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.to_str().unwrap(), "serve", "--port", &port.to_string()])
        .spawn()
        .expect("spawn kiln-registry");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Registry { child };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("kiln-registry never started listening on 127.0.0.1:{port}");
}

fn add_user(data_dir: &Path, username: &str, password: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.to_str().unwrap(), "user", "add", username, password])
        .status()
        .expect("run kiln-registry user add");
    assert!(status.success());
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn push_token(port: u16, repo: &str, user: &str, pass: &str) -> String {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        token: String,
    }
    let resp: TokenResponse = ureq::get(&format!("http://127.0.0.1:{port}/token"))
        .query("service", "test")
        .query("scope", &format!("repository:{repo}:pull,push"))
        .set("Authorization", &format!("Basic {}", base64_basic(user, pass)))
        .call()
        .expect("get push token")
        .into_json()
        .expect("parse token response");
    resp.token
}

fn base64_basic(user: &str, pass: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{pass}");
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn push_blob(port: u16, repo: &str, token: &str, content: &[u8]) -> String {
    let digest = digest_of(content);
    let start = ureq::post(&format!("http://127.0.0.1:{port}/v2/{repo}/blobs/uploads/"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .expect("start blob upload");
    let location = start.header("Location").expect("Location header").to_string();
    ureq::put(&format!("http://127.0.0.1:{port}{location}?digest={digest}"))
        .set("Authorization", &format!("Bearer {token}"))
        .send_bytes(content)
        .expect("complete blob upload");
    digest
}

fn push_manifest(port: u16, repo: &str, tag: &str, token: &str, config_digest: &str, layer_digests: &[&str]) {
    let layers: Vec<_> = layer_digests.iter().map(|d| serde_json::json!({ "digest": d, "size": 0 })).collect();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": { "digest": config_digest, "size": 0 },
        "layers": layers,
    });
    ureq::put(&format!("http://127.0.0.1:{port}/v2/{repo}/manifests/{tag}"))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(manifest)
        .expect("push manifest");
}

#[test]
fn gc_removes_only_blobs_no_manifest_references() {
    let data_dir = tempfile::tempdir().unwrap();
    let port = 15991;

    add_user(data_dir.path(), "gcuser", "gcpass");
    let repo = "gcuser/img";

    {
        let _registry = spawn_registry(data_dir.path(), port);
        let token = push_token(port, repo, "gcuser", "gcpass");

        let config_digest = push_blob(port, repo, &token, b"config-blob");
        let layer_digest = push_blob(port, repo, &token, b"layer-blob");
        let orphan_digest = push_blob(port, repo, &token, b"orphan-blob");

        // Only config+layer are referenced by the manifest actually
        // pushed - the third blob is uploaded but never referenced,
        // exactly the "aborted push" shape a real orphan comes from.
        push_manifest(port, repo, "v1", &token, &config_digest, &[&layer_digest]);

        let blob_path = |digest: &str| data_dir.path().join("blobs").join("sha256").join(digest.strip_prefix("sha256:").unwrap());
        assert!(blob_path(&config_digest).exists());
        assert!(blob_path(&layer_digest).exists());
        assert!(blob_path(&orphan_digest).exists());

        // _registry dropped (killed) at the end of this block, so the
        // `kiln-registry gc` subprocess below isn't racing a live server
        // still holding the data dir.
    }

    let blob_path = |digest: &str| data_dir.path().join("blobs").join("sha256").join(digest.strip_prefix("sha256:").unwrap());
    let orphan_digest = digest_of(b"orphan-blob");
    let config_digest = digest_of(b"config-blob");
    let layer_digest = digest_of(b"layer-blob");

    // --dry-run: reports the orphan, but doesn't touch anything.
    let dry_run_output = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "gc", "--dry-run"])
        .output()
        .expect("run kiln-registry gc --dry-run");
    let dry_run_stdout = String::from_utf8_lossy(&dry_run_output.stdout);
    assert!(
        dry_run_stdout.contains("would remove 1 blob"),
        "unexpected dry-run output: {dry_run_stdout:?}"
    );
    assert!(blob_path(&orphan_digest).exists(), "dry-run must not actually delete anything");

    // A real run actually deletes the orphan, and only the orphan.
    let real_output = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "gc"])
        .output()
        .expect("run kiln-registry gc");
    let real_stdout = String::from_utf8_lossy(&real_output.stdout);
    assert!(real_stdout.contains("removed 1 blob"), "unexpected gc output: {real_stdout:?}");
    assert!(!blob_path(&orphan_digest).exists(), "orphaned blob should be gone");
    assert!(blob_path(&config_digest).exists(), "referenced config blob must survive gc");
    assert!(blob_path(&layer_digest).exists(), "referenced layer blob must survive gc");
}
