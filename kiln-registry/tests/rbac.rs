//! Real-server proof that kiln-registry's per-account role model
//! (push/pull/admin) and the "pull now requires real credentials" change
//! are both actually enforced by the running server - not just
//! internally consistent in `handlers.rs`. Drives the real compiled
//! `kiln-registry` binary end-to-end over HTTP, same style as
//! `kilnd/tests/api.rs`.

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

fn add_user(data_dir: &Path, username: &str, password: &str, role: Option<&str>) {
    let mut args = vec!["--data-dir", data_dir.to_str().unwrap(), "user", "add", username, password];
    if let Some(r) = role {
        args.push("--role");
        args.push(r);
    }
    let status = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(&args)
        .status()
        .expect("run kiln-registry user add");
    assert!(status.success(), "user add {username} failed");
}

/// Requests a token for `repository`/`actions`, with optional Basic auth,
/// and returns just the HTTP status - callers only care whether the
/// server granted or refused it, never the token value itself.
fn token_status(port: u16, repository: &str, actions: &str, creds: Option<(&str, &str)>) -> u16 {
    let url = format!("http://127.0.0.1:{port}/token?service=test&scope=repository:{repository}:{actions}");
    let mut req = ureq::get(&url);
    if let Some((user, pass)) = creds {
        req = req.set("Authorization", &format!("Basic {}", base64_basic(user, pass)));
    }
    match req.call() {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(_) => 0,
    }
}

/// Minimal base64 encode, just for this test's own `Authorization: Basic`
/// header - not worth a whole dependency for one test-only call site.
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

#[test]
fn role_model_gates_push_and_pull_as_designed() {
    let data_dir = tempfile::tempdir().unwrap();
    let port = 15971;

    add_user(data_dir.path(), "alice", "alicepass", None); // no --role: defaults to push
    add_user(data_dir.path(), "bob", "bobpass", Some("pull"));
    add_user(data_dir.path(), "root", "rootpass", Some("admin"));

    let _registry = spawn_registry(data_dir.path(), port);

    // No credentials at all: even a bare pull scope is now refused - the
    // whole point of this chantier's chosen scope.
    assert_eq!(
        token_status(port, "alice/app", "pull", None),
        401,
        "anonymous pull should now be rejected"
    );

    // alice (push role, the default): can pull and push her own
    // namespace...
    assert_eq!(token_status(port, "alice/app", "pull", Some(("alice", "alicepass"))), 200);
    assert_eq!(token_status(port, "alice/app", "push", Some(("alice", "alicepass"))), 200);
    // ...but not bob's.
    assert_eq!(token_status(port, "bob/app", "push", Some(("alice", "alicepass"))), 403);

    // bob (pull role): can pull anything once authenticated, but can
    // never push - not even to his own namespace.
    assert_eq!(token_status(port, "alice/app", "pull", Some(("bob", "bobpass"))), 200);
    assert_eq!(token_status(port, "bob/app", "push", Some(("bob", "bobpass"))), 403);

    // root (admin role): can push to anyone's namespace.
    assert_eq!(token_status(port, "alice/app", "push", Some(("root", "rootpass"))), 200);
    assert_eq!(token_status(port, "bob/app", "push", Some(("root", "rootpass"))), 200);

    // Wrong password: rejected regardless of role.
    assert_eq!(token_status(port, "alice/app", "pull", Some(("alice", "wrongpass"))), 401);
}

#[test]
fn set_role_changes_an_existing_account_without_touching_its_password() {
    let data_dir = tempfile::tempdir().unwrap();
    let port = 15972;

    add_user(data_dir.path(), "carol", "carolpass", Some("pull"));

    let status = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.path().to_str().unwrap(), "user", "set-role", "carol", "push"])
        .status()
        .expect("run kiln-registry user set-role");
    assert!(status.success());

    let _registry = spawn_registry(data_dir.path(), port);

    // Password from the original `add` still works...
    assert_eq!(token_status(port, "carol/app", "pull", Some(("carol", "carolpass"))), 200);
    // ...and the role change actually took effect: carol can now push.
    assert_eq!(token_status(port, "carol/app", "push", Some(("carol", "carolpass"))), 200);
}
