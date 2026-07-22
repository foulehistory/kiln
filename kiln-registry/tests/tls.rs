//! Real TLS listener test: generates a leaf certificate via `openssl`
//! (skipped if not on `PATH` - matches this project's other "skip if an
//! external tool is missing" tests, e.g. the vulnerability scan tests'
//! `trivy` check), starts the real compiled `kiln-registry` binary with
//! `--tls-cert`/`--tls-key`, and drives a real `rustls` client connection
//! against it (trusting only the generated test cert, not any public
//! CA - proving the server's own TLS handshake and HTTP layer work,
//! without needing a publicly-trusted certificate this test can't
//! obtain). Also confirms a plain (non-TLS) connection to the same port
//! doesn't get a valid HTTP response, i.e. the port genuinely requires
//! TLS rather than silently still accepting plaintext.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
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

fn openssl_available() -> bool {
    Command::new("openssl").arg("version").output().is_ok()
}

/// A self-signed leaf certificate (not a CA cert - `basicConstraints=CA:FALSE`,
/// matching what a real server cert looks like) valid for `127.0.0.1`,
/// so the test client can connect by IP with no `/etc/hosts` entry.
fn generate_test_cert(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "basicConstraints=CA:FALSE",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ])
        .output()
        .expect("run openssl");
    assert!(
        status.status.success(),
        "openssl cert generation failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    (cert, key)
}

fn spawn_registry_tls(data_dir: &Path, port: u16, cert: &Path, key: &Path) -> Registry {
    let child = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "serve",
            "--port",
            &port.to_string(),
            "--tls-cert",
            cert.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
        ])
        .spawn()
        .expect("spawn kiln-registry");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Registry { child };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("kiln-registry never started listening on 127.0.0.1:{port}");
}

/// Loads `cert_path` as the *only* trusted root - a direct pin, not a
/// chain-to-a-public-CA validation (there is no public CA for a
/// locally-generated test cert) - then performs a real TLS handshake and
/// one raw HTTP request over it, returning the response's status line.
fn tls_get_v2(port: u16, cert_path: &Path) -> String {
    let cert_pem = std::fs::read(cert_path).expect("read test cert");
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .next()
        .expect("no cert in PEM")
        .expect("parsing test cert");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("adding test cert as a trusted root");

    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::new(127, 0, 0, 1).into());
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).expect("building TLS client connection");
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(b"GET /v2/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write request over TLS");
    let mut response = String::new();
    // A real TLS-close error after the server's `Connection: close`
    // response is expected here, not a test failure - `read_to_string`
    // returning `Err` once the peer has already sent everything and shut
    // the connection is normal for a non-keep-alive HTTP/1.1 exchange.
    let _ = tls.read_to_string(&mut response);
    response.lines().next().unwrap_or_default().to_string()
}

#[test]
fn tls_flag_makes_the_listener_speak_real_tls() {
    if !openssl_available() {
        eprintln!("skipping: openssl not on PATH");
        return;
    }

    let data_dir = tempfile::tempdir().unwrap();
    let cert_dir = tempfile::tempdir().unwrap();
    let port = 15981;

    let (cert, key) = generate_test_cert(cert_dir.path());
    let _registry = spawn_registry_tls(data_dir.path(), port, &cert, &key);

    let status_line = tls_get_v2(port, &cert);
    assert!(
        status_line.contains("401"),
        "expected the same 401 challenge a plain-HTTP ping() gets, over a real TLS connection: {status_line:?}"
    );

    // A plain-HTTP request to the same port should not get a valid HTTP
    // response back - the port only speaks TLS now.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    sock.write_all(b"GET /v2/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write plain request");
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.starts_with("HTTP/1.1"),
        "a plain-HTTP request to the TLS-only port shouldn't get a valid HTTP response: {text:?}"
    );
}
