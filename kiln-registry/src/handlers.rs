//! The subset of the OCI Distribution API that `kiln-image`'s registry
//! client actually emits (confirmed by reading `push`/`push_blob`/
//! `pull_layer` in `kiln-image/src/registry.rs`): single-shot blob
//! upload (`POST` then one `PUT`, no chunked `PATCH`), tag-addressed
//! manifests only, no manifest lists. Not a general-purpose registry
//! implementation - just enough for one Kiln instance to push and
//! another to pull.
//!
//! Reads (`GET`/`HEAD` on blobs and manifests) are always public - no
//! token is checked. Writes (`POST`/`PUT` on blobs and manifests)
//! require a Bearer token, obtained from `/token`, that was issued
//! `push` for that exact repository - which `/token` only grants to the
//! user whose username is the repository's first path segment (i.e. you
//! can push to `<your-username>/anything`, never anyone else's
//! namespace).

use crate::auth::{self, TokenStore};
use crate::store::RegistryStore;
use kilnd_core::conn::Conn;
use kilnd_core::http::{Request, Response};
use sha2::{Digest, Sha256};
use std::io;

pub fn route(store: &RegistryStore, tokens: &TokenStore, req: &Request, stream: &mut Conn) -> io::Result<()> {
    let segments: Vec<&str> = req.path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    let response = if segments == ["v2"] {
        ping(req)
    } else if segments == ["token"] {
        token_endpoint(store, tokens, req)
    } else if let ["users", username, "pubkey"] = segments.as_slice() {
        match req.method.as_str() {
            "GET" => get_pubkey(store, username),
            "PUT" => put_pubkey(store, req, username),
            _ => Response::text(404, "not found"),
        }
    } else if segments.first() == Some(&"v2") {
        match split_repo_and_op(&segments[1..]) {
            Some((repo, op)) => dispatch(store, tokens, req, &repo.join("/"), op),
            None => Response::text(404, "not found"),
        }
    } else {
        Response::text(404, "not found")
    };
    response.write_to(stream)
}

/// A repository name (per the OCI spec) never legally contains a
/// component literally equal to `blobs` or `manifests`, so the last such
/// component marks where the repository name ends and the operation
/// begins - `foulehistory/palworld/blobs/uploads/abc` splits into
/// `["foulehistory","palworld"]` + `["blobs","uploads","abc"]`. Scanning
/// from the end (rather than the first match) is what makes this correct
/// even for a repository with several path segments.
fn split_repo_and_op<'a>(segments: &'a [&'a str]) -> Option<(&'a [&'a str], &'a [&'a str])> {
    for i in (0..segments.len()).rev() {
        if segments[i] == "blobs" || segments[i] == "manifests" {
            if i == 0 {
                return None;
            }
            return Some((&segments[..i], &segments[i..]));
        }
    }
    None
}

fn dispatch(store: &RegistryStore, tokens: &TokenStore, req: &Request, repository: &str, op: &[&str]) -> Response {
    match (req.method.as_str(), op) {
        ("HEAD", ["blobs", digest]) => head_blob(store, digest),
        ("GET", ["blobs", digest]) => get_blob(store, digest),
        ("POST", ["blobs", "uploads"]) => start_upload(tokens, req, repository),
        ("PUT", ["blobs", "uploads", _id]) => complete_upload(store, tokens, req, repository),
        ("PUT", ["manifests", tag]) => put_manifest(store, tokens, req, repository, tag),
        ("GET", ["manifests", tag]) => get_manifest(store, repository, tag),
        ("PUT", ["manifests", tag, "signature"]) => put_signature(store, tokens, req, repository, tag),
        ("GET", ["manifests", tag, "signature"]) => get_signature(store, repository, tag),
        _ => Response::text(404, "not found"),
    }
}

/// Always challenges, even though reads never actually require a token -
/// this is what makes the client (`get_token`/`get_explicit_host_token`
/// in `kiln-image/src/registry.rs`) fetch one unconditionally, which is
/// the only way `/token` gets a chance to tell an anonymous pull apart
/// from an authenticated push later.
fn ping(req: &Request) -> Response {
    let host = req.headers.get("host").cloned().unwrap_or_else(|| "localhost".to_string());
    let scheme = req.headers.get("x-forwarded-proto").map(String::as_str).unwrap_or("http");
    Response {
        status: 401,
        headers: vec![("WWW-Authenticate".into(), format!("Bearer realm=\"{scheme}://{host}/token\",service=\"{host}\""))],
        body: Vec::new(),
    }
}

#[derive(serde::Serialize)]
struct TokenResponse {
    token: String,
}

/// `?service=...&scope=repository:<name>:<actions>` (`<actions>` comma
/// separated, e.g. `pull,push`), with an optional `Authorization: Basic`
/// header. A `pull`-only scope is always granted, even with no
/// credentials at all (public read). A scope that includes `push`
/// requires valid credentials for a user whose username matches `<name>`'s
/// first path segment - anyone can read anything, only the owner can
/// write to their own namespace.
fn token_endpoint(store: &RegistryStore, tokens: &TokenStore, req: &Request) -> Response {
    let Some(scope) = req.query.get("scope") else {
        return Response::text(400, "missing scope");
    };
    let Some((repository, actions)) = parse_scope(scope) else {
        return Response::text(400, "invalid scope");
    };

    if actions.iter().any(|a| a == "push") {
        let Some(username) = verify_basic_auth(store, req) else {
            return Response::text(401, "authentication required for push");
        };
        let owner = repository.split('/').next().unwrap_or("");
        if owner != username {
            return Response::text(403, format!("{username} may not push to {repository}"));
        }
    }

    let token = tokens.issue(repository, actions);
    Response::json(200, &TokenResponse { token })
}

/// `Some(username)` iff `req` carries a valid `Authorization: Basic`
/// header for a real account - shared by the `/token` push-scope check
/// and the `PUT /users/:username/pubkey` endpoint, both of which need
/// "prove you are this account" rather than the Bearer-token flow used
/// for repository actions.
fn verify_basic_auth(store: &RegistryStore, req: &Request) -> Option<String> {
    let (username, password) = basic_auth(req)?;
    let user = store.find_user(&username)?;
    if auth::verify_password(&password, &user.password_hash) {
        Some(username)
    } else {
        None
    }
}

fn parse_scope(scope: &str) -> Option<(String, Vec<String>)> {
    let rest = scope.strip_prefix("repository:")?;
    let (name, actions) = rest.rsplit_once(':')?;
    Some((name.to_string(), actions.split(',').map(str::to_string).collect()))
}

fn basic_auth(req: &Request) -> Option<(String, String)> {
    let header = req.headers.get("authorization")?;
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = base64_decode(encoded)?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &c) in BASE64_ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| table[b as usize]).collect();
        if vals.iter().any(|&v| v == 255) {
            return None;
        }
        out.push((vals[0] << 2) | (vals.get(1).copied().unwrap_or(0) >> 4));
        if vals.len() > 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() > 3 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

fn bearer_token(req: &Request) -> Option<&str> {
    req.headers.get("authorization")?.strip_prefix("Bearer ")
}

fn head_blob(store: &RegistryStore, digest: &str) -> Response {
    if store.blob_exists(digest) {
        Response { status: 200, headers: Vec::new(), body: Vec::new() }
    } else {
        Response::text(404, "blob not found")
    }
}

fn get_blob(store: &RegistryStore, digest: &str) -> Response {
    match store.blob_path(digest).and_then(|p| crate::store::read_file(&p)) {
        Some(bytes) => Response { status: 200, headers: vec![("Content-Type".into(), "application/octet-stream".into())], body: bytes },
        None => Response::text(404, "blob not found"),
    }
}

/// No upload session state is kept between this and the `PUT` that
/// follows - the client (`push_blob`) sends the *entire* blob in one
/// `PUT` to whatever `Location` this returns, carrying its own bearer
/// token again, so there's nothing this step needs to remember. The
/// upload id in the URL exists only to satisfy clients that expect one;
/// it's never looked up server-side.
fn start_upload(tokens: &TokenStore, req: &Request, repository: &str) -> Response {
    if !bearer_token(req).is_some_and(|t| tokens.validate(t, repository, "push")) {
        return Response::text(401, "push token required");
    }
    let id = random_id();
    Response {
        status: 202,
        headers: vec![("Location".into(), format!("/v2/{repository}/blobs/uploads/{id}"))],
        body: Vec::new(),
    }
}

fn complete_upload(store: &RegistryStore, tokens: &TokenStore, req: &Request, repository: &str) -> Response {
    if !bearer_token(req).is_some_and(|t| tokens.validate(t, repository, "push")) {
        return Response::text(401, "push token required");
    }
    let Some(digest) = req.query.get("digest") else {
        return Response::text(400, "missing digest query param");
    };
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(&req.body)));
    if &actual != digest {
        return Response::text(400, format!("digest mismatch: expected {digest}, got {actual}"));
    }
    match store.write_blob(digest, &req.body) {
        Some(Ok(())) => Response { status: 201, headers: Vec::new(), body: Vec::new() },
        Some(Err(e)) => Response::text(500, format!("writing blob: {e}")),
        None => Response::text(400, "invalid digest"),
    }
}

fn put_manifest(store: &RegistryStore, tokens: &TokenStore, req: &Request, repository: &str, tag: &str) -> Response {
    if !bearer_token(req).is_some_and(|t| tokens.validate(t, repository, "push")) {
        return Response::text(401, "push token required");
    }
    match store.write_manifest(repository, tag, &req.body) {
        Some(Ok(())) => Response { status: 201, headers: Vec::new(), body: Vec::new() },
        Some(Err(e)) => Response::text(500, format!("writing manifest: {e}")),
        None => Response::text(400, "invalid tag"),
    }
}

/// Only tag-addressed lookups are supported - see `RegistryStore::manifest_path`'s
/// own doc comment for why that's enough for what this server is for.
fn get_manifest(store: &RegistryStore, repository: &str, tag: &str) -> Response {
    match store.manifest_path(repository, tag).and_then(|p| crate::store::read_file(&p)) {
        Some(bytes) => Response {
            status: 200,
            headers: vec![("Content-Type".into(), "application/vnd.oci.image.manifest.v1+json".into())],
            body: bytes,
        },
        None => Response::text(404, "manifest not found"),
    }
}

fn put_signature(store: &RegistryStore, tokens: &TokenStore, req: &Request, repository: &str, tag: &str) -> Response {
    if !bearer_token(req).is_some_and(|t| tokens.validate(t, repository, "push")) {
        return Response::text(401, "push token required");
    }
    match store.write_signature(repository, tag, &req.body) {
        Some(Ok(())) => Response { status: 201, headers: Vec::new(), body: Vec::new() },
        Some(Err(e)) => Response::text(500, format!("writing signature: {e}")),
        None => Response::text(400, "invalid tag"),
    }
}

/// Public, like `get_manifest` - anyone pulling needs to be able to fetch
/// a signature to verify it, without first needing a token.
fn get_signature(store: &RegistryStore, repository: &str, tag: &str) -> Response {
    match store.signature_path(repository, tag).and_then(|p| crate::store::read_file(&p)) {
        Some(bytes) => Response { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: bytes },
        None => Response::text(404, "no signature for this manifest"),
    }
}

#[derive(serde::Serialize)]
struct PubkeyResponse {
    public_key: String,
}

/// Public - a puller needs to fetch the repository owner's key without
/// authenticating as anyone.
fn get_pubkey(store: &RegistryStore, username: &str) -> Response {
    match store.find_user(username).and_then(|u| u.public_key) {
        Some(public_key) => Response::json(200, &PubkeyResponse { public_key }),
        None => Response::text(404, "no public key on file for this user"),
    }
}

/// Self-service: `username` in the URL must match the account
/// `Authorization: Basic` authenticates as - nobody can set another
/// user's key, mirroring the same "prove you own this namespace" shape
/// already used for push authorization.
fn put_pubkey(store: &RegistryStore, req: &Request, username: &str) -> Response {
    let Some(authenticated) = verify_basic_auth(store, req) else {
        return Response::text(401, "authentication required");
    };
    if authenticated != username {
        return Response::text(403, "cannot set another user's public key");
    }
    #[derive(serde::Deserialize)]
    struct Body {
        public_key: String,
    }
    let body: Body = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    match store.set_public_key(username, &body.public_key) {
        Ok(()) => Response::json(200, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(500, format!("saving public key: {e}")),
    }
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
