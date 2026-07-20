//! A minimal, single-file OCI Distribution registry server - just enough
//! of the API surface `kiln-image::registry`'s push/pull actually use, so
//! `kiln push`/`kiln pull` can be tested end-to-end against something real
//! without needing credentials for (or the ability to touch) an actual
//! public registry. Not a production registry: no auth, single-threaded
//! (one connection at a time), everything held in a flat directory on
//! disk. See `kiln-image/src/registry.rs`'s module docs for the client
//! side of this - an explicit-host reference like `localhost:5555/echo`
//! talks to a server like this one over plain HTTP with no auth.
//!
//! Usage: `cargo run --example mini-registry -- <data-dir> [port]`
//! (defaults to port 5555).

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

fn main() {
    let mut args = env::args().skip(1);
    let data_dir = PathBuf::from(args.next().unwrap_or_else(|| {
        eprintln!("usage: mini-registry <data-dir> [port]");
        std::process::exit(1);
    }));
    let port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5555);

    fs::create_dir_all(data_dir.join("blobs")).expect("creating blobs dir");
    fs::create_dir_all(data_dir.join("manifests")).expect("creating manifests dir");

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("binding listener");
    println!("mini-registry: listening on http://127.0.0.1:{port}, data in {}", data_dir.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle(stream, &data_dir) {
                    eprintln!("mini-registry: connection error: {e}");
                }
            }
            Err(e) => eprintln!("mini-registry: accept error: {e}"),
        }
    }
}

struct Request {
    method: String,
    path: String,
    content_length: usize,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(v) = line
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .map(str::to_string)
        {
            content_length = v.parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    Ok(Request {
        method,
        path,
        content_length,
        body,
    })
}

fn write_response(stream: &mut TcpStream, status: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> std::io::Result<()> {
    write!(stream, "HTTP/1.1 {status} {reason}\r\n")?;
    for (k, v) in headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Blob digests (`sha256:<hex>`) are stored under their hex part directly -
/// safe as a filename (fixed-length hex) with no path-traversal risk.
fn blob_path(data_dir: &Path, digest: &str) -> PathBuf {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    data_dir.join("blobs").join(hex)
}

/// `repository` can itself contain `/` (e.g. `library/busybox`); the tag
/// is always the final path component, so this is safe to nest directly.
fn manifest_path(data_dir: &Path, repository: &str, reference: &str) -> PathBuf {
    data_dir.join("manifests").join(repository).join(reference)
}

fn handle(mut stream: TcpStream, data_dir: &Path) -> std::io::Result<()> {
    let req = read_request(&mut stream)?;
    println!("{} {} ({} byte body)", req.method, req.path, req.content_length);

    let path = req.path.as_str();

    // POST /v2/<repo>/blobs/uploads/
    if req.method == "POST" {
        if let Some(repo) = path.strip_prefix("/v2/").and_then(|p| p.strip_suffix("/blobs/uploads/")) {
            let upload_id = format!("{:x}", rand_u64());
            let location = format!("/v2/{repo}/blobs/uploads/{upload_id}");
            return write_response(&mut stream, 202, "Accepted", &[("Location", &location)], b"");
        }
    }

    // PUT /v2/<repo>/blobs/uploads/<id>?digest=<digest> (the Location this
    // server handed back from the POST above, plus ?digest= appended by
    // the client)
    if req.method == "PUT" {
        if let Some(rest) = path.strip_prefix("/v2/") {
            if let Some((repo_and_uploads, query)) = rest.split_once('?') {
                if repo_and_uploads.contains("/blobs/uploads/") {
                    let digest = query.split('&').find_map(|kv| kv.strip_prefix("digest=")).unwrap_or_default();
                    let actual = format!("sha256:{}", hex_encode(&Sha256::digest(&req.body)));
                    if !digest.is_empty() && digest != actual {
                        let msg = format!("digest mismatch: expected {digest}, got {actual}");
                        return write_response(&mut stream, 400, "Bad Request", &[], msg.as_bytes());
                    }
                    let path = blob_path(data_dir, digest);
                    fs::create_dir_all(path.parent().unwrap())?;
                    fs::write(&path, &req.body)?;
                    return write_response(&mut stream, 201, "Created", &[], b"");
                }
            }
        }
    }

    // PUT /v2/<repo>/manifests/<tag>
    if req.method == "PUT" {
        if let Some(rest) = path.strip_prefix("/v2/") {
            if let Some((repo, reference)) = rest.split_once("/manifests/") {
                let mpath = manifest_path(data_dir, repo, reference);
                fs::create_dir_all(mpath.parent().unwrap())?;
                fs::write(&mpath, &req.body)?;
                return write_response(&mut stream, 201, "Created", &[], b"");
            }
        }
    }

    // GET/HEAD /v2/<repo>/manifests/<tag>
    if req.method == "GET" || req.method == "HEAD" {
        if let Some(rest) = path.strip_prefix("/v2/") {
            if let Some((repo, reference)) = rest.split_once("/manifests/") {
                let mpath = manifest_path(data_dir, repo, reference);
                return match fs::read(&mpath) {
                    Ok(data) => {
                        let body = if req.method == "HEAD" { &[][..] } else { &data[..] };
                        write_response(
                            &mut stream,
                            200,
                            "OK",
                            &[("Content-Type", "application/vnd.oci.image.manifest.v1+json")],
                            body,
                        )
                    }
                    Err(_) => write_response(&mut stream, 404, "Not Found", &[], b"manifest not found"),
                };
            }
        }
    }

    // GET/HEAD /v2/<repo>/blobs/<digest>
    if req.method == "GET" || req.method == "HEAD" {
        if let Some(rest) = path.strip_prefix("/v2/") {
            if let Some((_repo, digest)) = rest.split_once("/blobs/") {
                let bpath = blob_path(data_dir, digest);
                return match fs::read(&bpath) {
                    Ok(data) => {
                        let body = if req.method == "HEAD" { &[][..] } else { &data[..] };
                        write_response(&mut stream, 200, "OK", &[("Content-Type", "application/octet-stream")], body)
                    }
                    Err(_) => write_response(&mut stream, 404, "Not Found", &[], b"blob not found"),
                };
            }
        }
    }

    if path == "/v2/" || path == "/v2" {
        return write_response(&mut stream, 200, "OK", &[], b"{}");
    }

    write_response(&mut stream, 404, "Not Found", &[], b"no route")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Just needs to be unique-enough for concurrent upload session ids in a
/// single-user local test tool - not a security boundary.
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64;
    let pid = std::process::id() as u64;
    nanos ^ (pid << 32)
}
