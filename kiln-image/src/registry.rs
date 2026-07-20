//! A minimal OCI Distribution (registry) client: enough to **pull** and
//! **push** images and convert their layers into Kiln's own
//! content-addressed format.
//!
//! Two kinds of registry are supported, distinguished by [`Reference`]
//! parsing (same heuristic `docker`/`crane` use: a reference's first path
//! segment is a host, not part of the repository, if it contains a `.` or
//! `:` or is literally `localhost`):
//!
//! - **Docker Hub** (no explicit host, e.g. `busybox`, `library/debian`):
//!   `https://registry-1.docker.io`, with the anonymous-token Bearer auth
//!   dance Docker Hub requires for every pull and push.
//! - **An explicit host** (e.g. `localhost:5555/echo`,
//!   `myregistry.example.com/app`): HTTPS by default (see
//!   [`Reference::base_url`] for the `localhost`/`http://`-prefix escape
//!   hatches), with the standard OCI Distribution auth flow - ping
//!   `/v2/`, and if it 401s with a `WWW-Authenticate: Bearer` challenge,
//!   fetch a token from the realm it names, using
//!   `KILN_REGISTRY_USER`/`KILN_REGISTRY_PASS` as HTTP Basic auth if
//!   set. A registry that doesn't challenge at all is treated as fully
//!   open (no token sent).
//!
//! # Converting OCI layers to Kiln layers
//!
//! An OCI layer is a gzipped tar; a Kiln layer ([`crate::layer`]) is a
//! JSON list of content-addressed entries. Pulling means streaming the tar
//! straight through the blob store (each regular file's content is hashed
//! and stored as it's read, never buffered whole), while translating two
//! OCI/tar-specific conventions into Kiln's overlayfs-native ones (see
//! `layer.rs`'s module docs for why the *materialized* form uses real
//! overlayfs whiteouts rather than inventing another convention of its
//! own):
//!
//! - A regular, typically-empty file named `.wh.<name>` marks `<name>` as
//!   deleted relative to lower layers -> becomes [`EntryKind::Whiteout`].
//! - A file named `.wh..wh..opq` inside a directory marks that directory
//!   as *opaque* (it replaces the lower directory of the same path
//!   wholesale, rather than merging with it) -> sets `Dir { opaque: true }`
//!   on that directory's entry.
//!
//! Tar hardlinks (a second path pointing at content already emitted
//! earlier in the *same* layer) are resolved by reusing that earlier
//! entry's blob hash - which, being content-addressed, is a hardlink in
//! every sense that matters without needing a dedicated `EntryKind` for
//! it. A hardlink whose target isn't in the same layer (e.g. targeting a
//! file from a lower layer) is rare in practice and is treated as an
//! error rather than silently producing a broken image.

use crate::error::{Error, Result};
use crate::image::{Image, ImageConfig};
use crate::layer::{Entry, EntryKind, LayerManifest};
use crate::store::{Hash, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;

const DOCKER_HUB_REGISTRY: &str = "https://registry-1.docker.io";
const DOCKER_HUB_AUTH: &str = "https://auth.docker.io/token";
const DOCKER_HUB_SERVICE: &str = "registry.docker.io";

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json";

/// A `name[:tag]` or `name@digest` reference to a remote image, optionally
/// prefixed with an explicit registry host (`host[:port]/repository`). With
/// no explicit host, the classic "no slash means an official image"
/// shorthand is applied, so `busybox` resolves to `library/busybox`,
/// matching `docker pull busybox`, and the target is Docker Hub.
#[derive(Debug, Clone)]
pub struct Reference {
    /// `Some("localhost:5555")` etc. for an explicit registry host; `None`
    /// means Docker Hub.
    pub host: Option<String>,
    pub repository: String,
    pub tag: String,
}

impl Reference {
    pub fn parse(s: &str) -> Self {
        let (repo, tag) = match s.split_once('@') {
            Some((repo, digest)) => (repo.to_string(), digest.to_string()),
            None => {
                let (name, tag) = crate::image::split_name_tag(s);
                (name.to_string(), tag.to_string())
            }
        };

        match repo.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                // `normalize_repository` here too, not just for the Docker
                // Hub branch below: without it, pulling a bare (no further
                // `/`) repository name from an explicit host tags it
                // locally under that bare name alone (e.g. `base/latest`),
                // which `Image::resolve` can never find again - it always
                // normalizes a bare name to `library/<name>` before
                // looking up a tag, on the assumption (stated in
                // `normalize_repository`'s own doc comment) that pull
                // already saved it under that same normalized name.
                Reference {
                    host: Some(first.to_string()),
                    repository: crate::image::normalize_repository(rest),
                    tag,
                }
            }
            _ => Reference {
                host: None,
                repository: crate::image::normalize_repository(&repo),
                tag,
            },
        }
    }

    /// The registry's API base (e.g. `https://registry-1.docker.io` or
    /// `http://localhost:5555`) - everything before `/v2/...`.
    ///
    /// Explicit hosts default to HTTPS - no real registry accepts plain
    /// HTTP, and this is what lets a self-hosted registry (see
    /// `kiln-registry`) sit behind a normal TLS-terminating reverse
    /// proxy with zero extra client config. Two escape hatches: a host
    /// already prefixed with `http://`/`https://` is used verbatim (for
    /// a registry not reachable at the "obvious" scheme), and
    /// `localhost`/`127.0.0.1` default to plain HTTP since a local dev
    /// registry has no certificate to offer.
    fn base_url(&self) -> String {
        match &self.host {
            Some(h) if h.starts_with("http://") || h.starts_with("https://") => h.clone(),
            Some(h) if h == "localhost" || h.starts_with("localhost:") || h == "127.0.0.1" || h.starts_with("127.0.0.1:") => {
                format!("http://{h}")
            }
            Some(h) => format!("https://{h}"),
            None => DOCKER_HUB_REGISTRY.to_string(),
        }
    }
}

/// Attach `Authorization: Bearer <token>` if there is one - Docker Hub
/// always needs one, an explicit-host registry never does (see the module
/// docs: no auth support for those yet).
fn with_auth(req: ureq::Request, token: Option<&str>) -> ureq::Request {
    match token {
        Some(t) => req.set("Authorization", &format!("Bearer {t}")),
        None => req,
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

/// `Some(token)` for Docker Hub, which always requires one - even for
/// anonymous, public pulls. For an explicit-host registry, delegates to
/// [`get_explicit_host_token`], which itself resolves to `None` for one
/// that doesn't challenge for auth at all.
fn get_token(reference: &Reference) -> Result<Option<String>> {
    match &reference.host {
        Some(_) => get_explicit_host_token(&reference.base_url(), &reference.repository, "pull"),
        None => {
            let repository = &reference.repository;
            let url = format!("{DOCKER_HUB_AUTH}?service={DOCKER_HUB_SERVICE}&scope=repository:{repository}:pull");
            let resp = ureq::get(&url)
                .call()
                .map_err(|e| Error::Registry(format!("requesting pull token for {repository}: {e}")))?;
            let parsed: TokenResponse = resp.into_json().map_err(|e| Error::Registry(format!("parsing token response: {e}")))?;
            Ok(Some(parsed.token))
        }
    }
}

/// For an explicit-host registry: ping `/v2/` to see whether it challenges
/// for auth at all, and if so, fetch a Bearer token for `scope_action`
/// (`"pull"` or `"pull,push"`) against the realm it names - the standard
/// OCI Distribution auth flow, the same shape as Docker Hub's own (just
/// discovered from the registry's challenge instead of hardcoded to one
/// specific auth server). `KILN_REGISTRY_USER`/`KILN_REGISTRY_PASS`, if
/// set, are sent as HTTP Basic auth when fetching that token - the usual
/// way a registry ties an anonymous-looking token request to a real
/// identity.
fn get_explicit_host_token(base_url: &str, repository: &str, scope_action: &str) -> Result<Option<String>> {
    let ping_url = format!("{base_url}/v2/");
    let challenge = match ureq::get(&ping_url).call() {
        Ok(_) => return Ok(None),
        Err(ureq::Error::Status(401, resp)) => resp.header("WWW-Authenticate").map(|s| s.to_string()),
        Err(_) => None,
    };
    let Some(challenge) = challenge else { return Ok(None) };
    let Some((realm, service)) = parse_bearer_challenge(&challenge) else {
        return Ok(None);
    };

    let scope = format!("repository:{repository}:{scope_action}");
    let separator = if realm.contains('?') { "&" } else { "?" };
    let token_url = format!("{realm}{separator}service={service}&scope={scope}");
    let mut req = ureq::get(&token_url);
    if let Some((user, pass)) = explicit_host_credentials() {
        req = req.set("Authorization", &format!("Basic {}", base64_encode(&format!("{user}:{pass}"))));
    }
    let resp = req.call().map_err(|e| Error::Registry(format!("requesting token from {realm}: {e}")))?;
    let parsed: TokenResponse = resp.into_json().map_err(|e| Error::Registry(format!("parsing token response: {e}")))?;
    Ok(Some(parsed.token))
}

/// `KILN_REGISTRY_USER`/`KILN_REGISTRY_PASS`, if both are set. Docker Hub
/// never consults this - its own token dance is always anonymous.
fn explicit_host_credentials() -> Option<(String, String)> {
    let user = std::env::var("KILN_REGISTRY_USER").ok()?;
    let pass = std::env::var("KILN_REGISTRY_PASS").ok()?;
    Some((user, pass))
}

/// Parse a `WWW-Authenticate: Bearer realm="...",service="...",...`
/// challenge header into `(realm, service)`. A registry that doesn't
/// challenge with `Bearer` at all (accepts Basic auth directly, or
/// requires nothing) yields `None`, which callers treat as "no token
/// needed here".
fn parse_bearer_challenge(header: &str) -> Option<(String, String)> {
    let rest = header.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = String::new();
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("realm=\"").and_then(|s| s.strip_suffix('"')) {
            realm = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("service=\"").and_then(|s| s.strip_suffix('"')) {
            service = v.to_string();
        }
    }
    Some((realm?, service))
}

/// A minimal base64 (standard alphabet, `=`-padded) encoder - just enough
/// for an HTTP Basic `Authorization` header, not worth a whole extra
/// dependency for.
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { CHARS[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Deserialize)]
struct ManifestListEntry {
    digest: String,
    platform: Platform,
}

#[derive(Deserialize)]
struct ManifestList {
    manifests: Vec<ManifestListEntry>,
}

#[derive(Deserialize)]
struct ManifestV2 {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Deserialize, Default)]
struct ContainerConfig {
    #[serde(default, rename = "Env")]
    env: Vec<String>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    working_dir: String,
    #[serde(default, rename = "ExposedPorts")]
    exposed_ports: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ImageConfigJson {
    config: Option<ContainerConfig>,
}

/// Returns the manifest both parsed *and* as the exact raw bytes the
/// registry sent - signature verification needs those exact bytes (the
/// same ones `push()` signed), not a re-serialization of `ManifestV2`
/// (a different, narrower struct than what actually got signed).
fn fetch_manifest(base_url: &str, repository: &str, reference: &str, token: Option<&str>) -> Result<(Vec<u8>, ManifestV2)> {
    let url = format!("{base_url}/v2/{repository}/manifests/{reference}");
    let req = with_auth(ureq::get(&url), token).set("Accept", MANIFEST_ACCEPT);
    let resp = req
        .call()
        .map_err(|e| Error::Registry(format!("fetching manifest {repository}:{reference}: {e}")))?;

    let content_type = resp.content_type().to_string();
    let body = resp.into_string().map_err(|e| Error::Registry(format!("reading manifest body: {e}")))?;

    if content_type.contains("manifest.list") || content_type.contains("image.index") {
        let list: ManifestList = serde_json::from_str(&body).map_err(|e| Error::Registry(format!("parsing manifest list: {e}")))?;
        let entry = list
            .manifests
            .iter()
            .find(|m| m.platform.architecture == "amd64" && m.platform.os == "linux")
            .ok_or_else(|| Error::Registry(format!("no linux/amd64 entry for {repository}:{reference}")))?;
        fetch_manifest(base_url, repository, &entry.digest, token)
    } else {
        let parsed = serde_json::from_str(&body).map_err(|e| Error::Registry(format!("parsing manifest: {e}")))?;
        Ok((body.into_bytes(), parsed))
    }
}

/// A reader that hashes every byte it passes through, so a blob's SHA-256
/// can be verified against its advertised digest without buffering the
/// whole (potentially large) blob in memory just to check it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

fn fetch_blob_reader(base_url: &str, repository: &str, digest: &str, token: Option<&str>) -> Result<HashingReader<Box<dyn Read>>> {
    let url = format!("{base_url}/v2/{repository}/blobs/{digest}");
    let resp = with_auth(ureq::get(&url), token)
        .call()
        .map_err(|e| Error::Registry(format!("fetching blob {digest}: {e}")))?;
    Ok(HashingReader {
        inner: resp.into_reader(),
        hasher: Sha256::new(),
    })
}

fn verify_digest(digest: &str, hasher: Sha256) -> Result<()> {
    let expected = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Registry(format!("unsupported digest algorithm in {digest:?} (only sha256 is supported)")))?;
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        return Err(Error::Registry(format!(
            "digest mismatch for {digest}: registry served content hashing to sha256:{actual}"
        )));
    }
    Ok(())
}

fn fetch_blob_bytes(base_url: &str, repository: &str, digest: &str, token: Option<&str>) -> Result<Vec<u8>> {
    let mut reader = fetch_blob_reader(base_url, repository, digest, token)?;
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| Error::Registry(format!("reading blob {digest}: {e}")))?;
    verify_digest(digest, reader.hasher)?;
    Ok(buf)
}

fn split_path(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((dir, base)) => (dir.to_string(), base.to_string()),
        None => (String::new(), path.to_string()),
    }
}

fn pull_layer(store: &Store, base_url: &str, repository: &str, digest: &str, token: Option<&str>) -> Result<Hash> {
    let reader = fetch_blob_reader(base_url, repository, digest, token)?;
    let gz = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(gz);

    let mut entries: Vec<Entry> = Vec::new();
    let mut path_to_blob: HashMap<String, (Hash, u64)> = HashMap::new();
    let mut pending_opaque: Vec<String> = Vec::new();

    let tar_entries = archive
        .entries()
        .map_err(|e| Error::Registry(format!("reading tar for layer {digest}: {e}")))?;

    for entry_result in tar_entries {
        let mut entry = entry_result.map_err(|e| Error::Registry(format!("reading tar entry in {digest}: {e}")))?;
        let raw_path = entry
            .path()
            .map_err(|e| Error::Registry(format!("reading tar entry path in {digest}: {e}")))?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        if raw_path.is_empty() || raw_path == "." {
            continue;
        }

        let mode = (entry.header().mode().unwrap_or(0o644)) & 0o7777;
        let uid = entry.header().uid().unwrap_or(0) as u32;
        let gid = entry.header().gid().unwrap_or(0) as u32;
        let entry_type = entry.header().entry_type();
        let (dir, base) = split_path(&raw_path);

        if let Some(stripped) = base.strip_prefix(".wh.") {
            if base == ".wh..wh..opq" {
                pending_opaque.push(dir);
            } else {
                let deleted_path = if dir.is_empty() {
                    stripped.to_string()
                } else {
                    format!("{dir}/{stripped}")
                };
                entries.push(Entry {
                    path: deleted_path,
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    kind: EntryKind::Whiteout,
                });
            }
            continue;
        }

        match entry_type {
            tar::EntryType::Directory => {
                entries.push(Entry {
                    path: raw_path,
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::Dir { opaque: false },
                });
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| Error::Registry(e.to_string()))?
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                entries.push(Entry {
                    path: raw_path,
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::Symlink { target },
                });
            }
            tar::EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| Error::Registry(e.to_string()))?
                    .map(|p| p.to_string_lossy().trim_start_matches("./").to_string())
                    .unwrap_or_default();
                let (blob, size) = path_to_blob.get(&target).copied().ok_or_else(|| {
                    Error::Registry(format!(
                        "layer {digest}: hardlink {raw_path:?} -> {target:?} references a path not seen earlier in the same layer (cross-layer hardlinks are not supported)"
                    ))
                })?;
                entries.push(Entry {
                    path: raw_path.clone(),
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::File { blob, size },
                });
                path_to_blob.insert(raw_path, (blob, size));
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let size = entry.header().size().unwrap_or(0);
                let blob = store.put_reader(&mut entry)?;
                entries.push(Entry {
                    path: raw_path.clone(),
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::File { blob, size },
                });
                path_to_blob.insert(raw_path, (blob, size));
            }
            tar::EntryType::Char | tar::EntryType::Block => {
                // Device nodes baked into a base image's own layers (e.g.
                // Debian's official images ship a handful of static
                // /dev/* entries from their own build process) - see
                // layer.rs's EntryKind::Device docs for why these must be
                // preserved rather than skipped: Kiln containers get no
                // /dev of their own beyond whatever the image provides.
                let major = entry
                    .header()
                    .device_major()
                    .map_err(|e| Error::Registry(format!("layer {digest}: reading device major for {raw_path:?}: {e}")))?
                    .unwrap_or(0);
                let minor = entry
                    .header()
                    .device_minor()
                    .map_err(|e| Error::Registry(format!("layer {digest}: reading device minor for {raw_path:?}: {e}")))?
                    .unwrap_or(0);
                entries.push(Entry {
                    path: raw_path,
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::Device {
                        char_device: entry_type == tar::EntryType::Char,
                        major: major as u64,
                        minor: minor as u64,
                    },
                });
            }
            tar::EntryType::Fifo => {
                entries.push(Entry {
                    path: raw_path,
                    mode,
                    uid,
                    gid,
                    kind: EntryKind::Fifo,
                });
            }
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => {
                // Pax extension headers carry no filesystem entry of
                // their own; the `tar` crate already folds the metadata
                // they carry into the *next* real entry.
                continue;
            }
            other => {
                return Err(Error::Registry(format!(
                    "layer {digest}: unsupported tar entry type {other:?} at {raw_path:?}"
                )));
            }
        }
    }

    for dir in pending_opaque {
        if let Some(existing) = entries.iter_mut().find(|e| e.path == dir && matches!(e.kind, EntryKind::Dir { .. })) {
            existing.kind = EntryKind::Dir { opaque: true };
        } else {
            entries.push(Entry {
                path: dir,
                mode: 0o755,
                uid: 0,
                gid: 0,
                kind: EntryKind::Dir { opaque: true },
            });
        }
    }

    entries.sort();
    LayerManifest { entries }.save(store)
}

/// Pull `reference` (e.g. `"busybox"`, `"busybox:1.36"`,
/// `"library/debian:bookworm"`, or `"localhost:5555/echo:latest"`),
/// convert it into Kiln's image format, save it to `store`, tag it as
/// `<repository>:<tag>`, and return its image id.
///
/// Signature verification only ever applies to an explicit-host registry
/// (Docker Hub has no notion of Kiln-native signatures at all, so
/// `reference.host.is_none()` skips this entirely, `skip_verify` or not).
/// For an explicit host, the default is to *require* a valid signature -
/// no signature, an unparseable one, or one that doesn't verify against
/// the repository owner's registered public key all fail the pull
/// outright. `skip_verify: true` (`kiln pull --insecure-skip-verify`)
/// bypasses this - a deliberate, visible opt-out rather than a permissive
/// default.
pub fn pull(store: &Store, reference: &str, skip_verify: bool) -> Result<Hash> {
    let reference = Reference::parse(reference);
    let base_url = reference.base_url();
    let token = get_token(&reference)?;
    let (manifest_bytes, manifest) = fetch_manifest(&base_url, &reference.repository, &reference.tag, token.as_deref())?;

    let mut verified = false;
    if reference.host.is_some() && !skip_verify {
        verify_signature(&base_url, &reference.repository, &reference.tag, &manifest_bytes, token.as_deref())?;
        verified = true;
    }

    let config_bytes = fetch_blob_bytes(&base_url, &reference.repository, &manifest.config.digest, token.as_deref())?;
    let image_config_json: ImageConfigJson =
        serde_json::from_slice(&config_bytes).map_err(|e| Error::Registry(format!("parsing image config: {e}")))?;
    let cc = image_config_json.config.unwrap_or_default();

    let mut config = ImageConfig::default();
    for kv in &cc.env {
        if let Some((k, v)) = kv.split_once('=') {
            config.env_set(k.to_string(), v.to_string());
        }
    }
    config.workdir = if cc.working_dir.is_empty() { "/".to_string() } else { cc.working_dir };
    config.cmd = cc.cmd.map(|parts| parts.join(" "));
    for port_proto in cc.exposed_ports.keys() {
        if let Some((port_str, proto)) = port_proto.split_once('/') {
            if let Ok(port) = port_str.parse() {
                config.exposed_ports.push((port, proto.to_string()));
            }
        }
    }

    let mut layers = Vec::new();
    for desc in &manifest.layers {
        layers.push(pull_layer(store, &base_url, &reference.repository, &desc.digest, token.as_deref())?);
    }

    let image = Image { layers, config };
    let image_id = image.save(store)?;
    store.tag(&reference.repository, &reference.tag, image_id)?;
    if verified {
        store.mark_signature_verified(image_id)?;
    }
    Ok(image_id)
}

#[derive(Deserialize)]
struct SignatureFile {
    signature: String,
}

#[derive(Deserialize)]
struct PubkeyResponse {
    public_key: String,
}

/// Fetches `<repo>:<tag>`'s signature and the repository owner's
/// registered public key, then verifies the signature covers exactly
/// `manifest_bytes`. Fails closed: any missing piece (no signature, owner
/// has no key on file) or a genuine verification failure is an error, not
/// a silent "treat as unsigned".
fn verify_signature(base_url: &str, repository: &str, tag: &str, manifest_bytes: &[u8], token: Option<&str>) -> Result<()> {
    let sig_url = format!("{base_url}/v2/{repository}/manifests/{tag}/signature");
    let sig_resp = with_auth(ureq::get(&sig_url), token).call().map_err(|e| {
        Error::Registry(format!(
            "{repository}:{tag} has no valid signature ({e}) - re-run with --insecure-skip-verify to pull anyway"
        ))
    })?;
    let sig_file: SignatureFile = sig_resp
        .into_json()
        .map_err(|e| Error::Registry(format!("parsing signature response: {e}")))?;

    let owner = repository.split('/').next().unwrap_or(repository);
    let pubkey_url = format!("{base_url}/users/{owner}/pubkey");
    let pubkey_resp = with_auth(ureq::get(&pubkey_url), token).call().map_err(|e| {
        Error::Registry(format!(
            "could not fetch {owner}'s public key ({e}) - re-run with --insecure-skip-verify to pull anyway"
        ))
    })?;
    let pubkey: PubkeyResponse = pubkey_resp
        .into_json()
        .map_err(|e| Error::Registry(format!("parsing public key response: {e}")))?;

    crate::signing::verify(&pubkey.public_key, manifest_bytes, &sig_file.signature)
        .map_err(|e| Error::Registry(format!("signature verification failed for {repository}:{tag}: {e}")))
}

// --- Push -------------------------------------------------------------
//
// Implemented against the standard OCI Distribution push flow (POST to
// start an upload session, PATCH/PUT the blob, PUT the manifest last so
// it's the one atomic "publish" step) - verified against a real registry
// (kiln-registry, this workspace's own) end to end, including the two
// auth bugs that surfaced doing so (see base_url's and get_push_token's
// own doc comments).

#[derive(Serialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Serialize)]
struct OciManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

/// `None` for an explicit-host registry (no auth support yet); `Some(token)` for Docker Hub.
fn get_push_token(reference: &Reference) -> Result<Option<String>> {
    match &reference.host {
        Some(_) => get_explicit_host_token(&reference.base_url(), &reference.repository, "pull,push"),
        None => {
            let repository = &reference.repository;
            let url = format!("{DOCKER_HUB_AUTH}?service={DOCKER_HUB_SERVICE}&scope=repository:{repository}:pull,push");
            let resp = ureq::get(&url)
                .call()
                .map_err(|e| Error::Registry(format!("requesting push token for {repository}: {e}")))?;
            let parsed: TokenResponse = resp.into_json().map_err(|e| Error::Registry(format!("parsing token response: {e}")))?;
            Ok(Some(parsed.token))
        }
    }
}

/// Upload `data` as a blob, if the registry doesn't already have it
/// (checked with a `HEAD` first, since re-uploading unchanged base-image
/// layers on every push would be wasteful).
fn push_blob(base_url: &str, repository: &str, digest: &str, data: &[u8], token: Option<&str>) -> Result<()> {
    let head_url = format!("{base_url}/v2/{repository}/blobs/{digest}");
    if with_auth(ureq::head(&head_url), token).call().is_ok() {
        return Ok(());
    }

    let start_url = format!("{base_url}/v2/{repository}/blobs/uploads/");
    let start_resp = with_auth(ureq::post(&start_url), token)
        .call()
        .map_err(|e| Error::Registry(format!("starting blob upload for {digest}: {e}")))?;
    let upload_url = start_resp
        .header("Location")
        .ok_or_else(|| Error::Registry("registry did not return an upload Location".into()))?
        .to_string();
    // A relative Location (just-path, e.g. "/v2/repo/blobs/uploads/<id>")
    // is legal per the Distribution spec; an absolute one is far more
    // common in practice, but handle both.
    let upload_url = if upload_url.starts_with('/') {
        format!("{base_url}{upload_url}")
    } else {
        upload_url
    };
    let separator = if upload_url.contains('?') { "&" } else { "?" };
    let put_url = format!("{upload_url}{separator}digest={digest}");

    with_auth(ureq::put(&put_url), token)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(data)
        .map_err(|e| Error::Registry(format!("uploading blob {digest}: {e}")))?;
    Ok(())
}

/// Push the image at `image_id` as `<reference>` - to Docker Hub, or to an
/// explicit-host registry if `reference` names one (see the module docs).
/// Reverses [`pull`]: materializes each Kiln layer, re-packs it as a
/// gzipped tar (OCI whiteout convention regenerated from our
/// overlayfs-native entries), and uploads config + layers + manifest.
pub fn push(store: &Store, image_id: &Hash, reference: &str) -> Result<()> {
    let reference = Reference::parse(reference);
    let base_url = reference.base_url();
    let token = get_push_token(&reference)?;
    let image = Image::load(store, image_id)?;

    let mut oci_layers = Vec::new();
    for layer_id in &image.layers {
        let manifest = LayerManifest::load(store, layer_id)?;
        let tar_gz = pack_layer_tar_gz(store, &manifest)?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&tar_gz)));
        push_blob(&base_url, &reference.repository, &digest, &tar_gz, token.as_deref())?;
        oci_layers.push(OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest,
            size: tar_gz.len() as u64,
        });
    }

    let config_json = build_oci_config_json(&image.config);
    let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_json)));
    push_blob(&base_url, &reference.repository, &config_digest, &config_json, token.as_deref())?;

    let manifest = OciManifest {
        schema_version: 2,
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        config: OciDescriptor {
            media_type: "application/vnd.oci.image.config.v1+json".to_string(),
            digest: config_digest,
            size: config_json.len() as u64,
        },
        layers: oci_layers,
    };
    let manifest_json = serde_json::to_vec(&manifest).map_err(|e| Error::Registry(e.to_string()))?;

    let manifest_url = format!("{base_url}/v2/{}/manifests/{}", reference.repository, reference.tag);
    with_auth(ureq::put(&manifest_url), token.as_deref())
        .set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
        .send_bytes(&manifest_json)
        .map_err(|e| Error::Registry(format!("pushing manifest: {e}")))?;

    // Signing only exists for an explicit-host registry (Docker Hub has
    // no notion of it), and only if the pusher has a local key configured
    // - unconfigured is the common case for anyone who only ever pulls,
    // and pushing unsigned is allowed (the *pull* side is what enforces
    // strictness, by default requiring what this step produces).
    if reference.host.is_some() {
        if let Some(signing_key) = crate::signing::load_signing_key() {
            sign_and_publish(
                &base_url,
                &reference.repository,
                &reference.tag,
                &manifest_json,
                &signing_key,
                token.as_deref(),
            )?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct SignaturePayload {
    algorithm: &'static str,
    signature: String,
}

#[derive(Serialize)]
struct PubkeyPayload {
    public_key: String,
}

/// Signs `manifest_json` (the exact bytes just pushed) and uploads both
/// the signature and the pusher's public key. Publishing the key on every
/// signed push (rather than requiring a separate one-time step) is
/// idempotent and self-healing - `kiln-registry`'s `PUT
/// /users/:username/pubkey` just overwrites, so there's no "did I already
/// publish it" state to track client-side.
fn sign_and_publish(
    base_url: &str,
    repository: &str,
    tag: &str,
    manifest_json: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    token: Option<&str>,
) -> Result<()> {
    let signature = crate::signing::sign(signing_key, manifest_json);
    let sig_url = format!("{base_url}/v2/{repository}/manifests/{tag}/signature");
    let sig_body = serde_json::to_vec(&SignaturePayload {
        algorithm: "ed25519",
        signature,
    })
    .map_err(|e| Error::Registry(e.to_string()))?;
    with_auth(ureq::put(&sig_url), token)
        .set("Content-Type", "application/json")
        .send_bytes(&sig_body)
        .map_err(|e| Error::Registry(format!("pushing signature: {e}")))?;

    // `PUT /users/:username/pubkey` is a "prove you are this account"
    // operation, not a repository action - it authenticates with the same
    // `Authorization: Basic` credentials used to *obtain* a push token in
    // the first place, not the push token itself (which only ever proves
    // "granted push on this one repository", nothing about account
    // identity beyond that).
    let owner = repository.split('/').next().unwrap_or(repository);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let pubkey_url = format!("{base_url}/users/{owner}/pubkey");
    let pubkey_body = serde_json::to_vec(&PubkeyPayload { public_key }).map_err(|e| Error::Registry(e.to_string()))?;
    let mut req = ureq::put(&pubkey_url).set("Content-Type", "application/json");
    if let Some((user, pass)) = explicit_host_credentials() {
        req = req.set("Authorization", &format!("Basic {}", base64_encode(&format!("{user}:{pass}"))));
    }
    req.send_bytes(&pubkey_body)
        .map_err(|e| Error::Registry(format!("publishing public key: {e}")))?;

    Ok(())
}

/// Uploads a vulnerability scan report as `<repository>:<tag>`'s sibling
/// `.../manifests/{tag}/scan-report` - the same "sibling file next to the
/// manifest, no new route needed" shape `sign_and_publish` already uses
/// for signatures. Called explicitly by `kiln push --scan` *after* a
/// successful push, not automatically from [`push`] itself - unlike
/// signing (which is silent/automatic whenever a local key exists),
/// scanning is opt-in and CLI-orchestrated, since `--block-on-critical`
/// needs to inspect the report and potentially refuse the push entirely
/// *before* any bytes go out.
pub fn push_scan_report(reference: &str, report: &crate::scan::ScanReport) -> Result<()> {
    let reference = Reference::parse(reference);
    let base_url = reference.base_url();
    let token = get_push_token(&reference)?;

    let url = format!("{base_url}/v2/{}/manifests/{}/scan-report", reference.repository, reference.tag);
    let body = serde_json::to_vec(report).map_err(|e| Error::Registry(e.to_string()))?;
    with_auth(ureq::put(&url), token.as_deref())
        .set("Content-Type", "application/json")
        .send_bytes(&body)
        .map_err(|e| Error::Registry(format!("pushing scan report: {e}")))?;
    Ok(())
}

/// Fetches `<repository>:<tag>`'s scan report, if one was ever pushed for
/// it - `Ok(None)` (not an error) if it was never scanned, since that's
/// the common case for most images, not a failure.
pub fn fetch_scan_report(reference: &str) -> Result<Option<crate::scan::ScanReport>> {
    let reference = Reference::parse(reference);
    let base_url = reference.base_url();
    let token = get_token(&reference)?;

    let url = format!("{base_url}/v2/{}/manifests/{}/scan-report", reference.repository, reference.tag);
    match with_auth(ureq::get(&url), token.as_deref()).call() {
        Ok(resp) => {
            let report = resp.into_json().map_err(|e| Error::Registry(format!("parsing scan report: {e}")))?;
            Ok(Some(report))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(Error::Registry(format!("fetching scan report: {e}"))),
    }
}

fn build_oci_config_json(config: &ImageConfig) -> Vec<u8> {
    let mut exposed = serde_json::Map::new();
    for (port, proto) in &config.exposed_ports {
        exposed.insert(format!("{port}/{proto}"), serde_json::json!({}));
    }
    let value = serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": config.env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
            "Cmd": config.cmd.as_ref().map(|c| vec!["/bin/sh", "-c", c]),
            "WorkingDir": config.workdir,
            "ExposedPorts": exposed,
        },
        "rootfs": { "type": "layers", "diff_ids": [] },
    });
    serde_json::to_vec(&value).expect("serialization cannot fail")
}

fn pack_layer_tar_gz(store: &Store, manifest: &LayerManifest) -> Result<Vec<u8>> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);

    // Kiln's content-addressed store means many `File` entries can share
    // the same blob (that's exactly how hardlinks - e.g. every busybox
    // applet pointing at one ~1MB binary - end up represented once a
    // layer's on disk). Without tracking that here, packing would embed
    // that same content again for every entry sharing it: busybox alone
    // has ~400 applet hardlinks, which turned a 4.4MB layer into ~430MB of
    // redundant gzip work - not an infinite loop, just minutes of real
    // work to produce a tar drastically larger than the actual content.
    // `pull_layer` already does the inverse translation (tar hardlink ->
    // shared blob); this is that, mirrored for push.
    let mut blob_to_path: HashMap<Hash, String> = HashMap::new();

    for entry in &manifest.entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(entry.mode);
        header.set_uid(entry.uid as u64);
        header.set_gid(entry.gid as u64);

        match &entry.kind {
            EntryKind::Dir { .. } => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{}/", entry.path), std::io::empty())
                    .map_err(|e| Error::Registry(format!("packing dir {}: {e}", entry.path)))?;
            }
            EntryKind::Symlink { target } => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                builder
                    .append_link(&mut header, &entry.path, target)
                    .map_err(|e| Error::Registry(format!("packing symlink {}: {e}", entry.path)))?;
            }
            EntryKind::Whiteout => {
                let (dir, base) = split_path(&entry.path);
                let wh_path = if dir.is_empty() {
                    format!(".wh.{base}")
                } else {
                    format!("{dir}/.wh.{base}")
                };
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, wh_path, std::io::empty())
                    .map_err(|e| Error::Registry(format!("packing whiteout {}: {e}", entry.path)))?;
            }
            EntryKind::Device { char_device, major, minor } => {
                header.set_entry_type(if *char_device { tar::EntryType::Char } else { tar::EntryType::Block });
                header
                    .set_device_major(*major as u32)
                    .map_err(|e| Error::Registry(format!("packing device {}: {e}", entry.path)))?;
                header
                    .set_device_minor(*minor as u32)
                    .map_err(|e| Error::Registry(format!("packing device {}: {e}", entry.path)))?;
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.path, std::io::empty())
                    .map_err(|e| Error::Registry(format!("packing device {}: {e}", entry.path)))?;
            }
            EntryKind::Fifo => {
                header.set_entry_type(tar::EntryType::Fifo);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.path, std::io::empty())
                    .map_err(|e| Error::Registry(format!("packing fifo {}: {e}", entry.path)))?;
            }
            EntryKind::File { blob, size } => {
                if let Some(first_path) = blob_to_path.get(blob) {
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_size(0);
                    builder
                        .append_link(&mut header, &entry.path, first_path)
                        .map_err(|e| Error::Registry(format!("packing hardlink {}: {e}", entry.path)))?;
                } else {
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(*size);
                    header.set_cksum();
                    let mut reader = store.open_blob(blob)?;
                    builder
                        .append_data(&mut header, &entry.path, &mut reader)
                        .map_err(|e| Error::Registry(format!("packing file {}: {e}", entry.path)))?;
                    blob_to_path.insert(*blob, entry.path.clone());
                }
            }
        }
    }

    let gz = builder.into_inner().map_err(|e| Error::Registry(format!("finishing tar: {e}")))?;
    gz.finish().map_err(|e| Error::Registry(format!("finishing gzip: {e}")))
}
