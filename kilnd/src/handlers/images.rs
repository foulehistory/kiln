use kiln_image::image::Image;
use kiln_image::layer::{EntryKind, LayerManifest};
use kiln_image::registry;
use kiln_image::store::{Hash, Store};
use kilnd_core::http::{Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize)]
pub struct ImageJson {
    pub id: String,
    pub repository: Option<String>,
    pub tag: Option<String>,
    pub layers: usize,
    /// Sum of *unique* blob sizes across this image's own layers - i.e.
    /// its real footprint after file-level dedup, not the naive sum of
    /// each layer's total content (which would double-count any file
    /// shared between two of this image's own layers).
    pub size_bytes: u64,
}

pub fn list(store: &Store) -> Response {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (repo, tag, id) in store.all_tags() {
        seen.insert(id);
        out.push(image_json(store, id, Some(repo), Some(tag)));
    }

    for id in store.all_image_ids() {
        if !seen.contains(&id) {
            out.push(image_json(store, id, None, None));
        }
    }

    Response::json(200, &out)
}

fn image_json(store: &Store, id: Hash, repository: Option<String>, tag: Option<String>) -> ImageJson {
    let mut layers = 0;
    let mut size_bytes = 0u64;

    if let Ok(img) = Image::load(store, &id) {
        layers = img.layers.len();
        let mut seen_blobs = HashSet::new();
        for layer_id in &img.layers {
            let Ok(manifest) = LayerManifest::load(store, layer_id) else { continue };
            for entry in &manifest.entries {
                if let EntryKind::File { blob, size } = &entry.kind {
                    if seen_blobs.insert(*blob) {
                        size_bytes += size;
                    }
                }
            }
        }
    }

    ImageJson {
        id: id.to_string(),
        repository,
        tag,
        layers,
        size_bytes,
    }
}

#[derive(Serialize)]
pub struct LayerDetailJson {
    pub hash: String,
    pub entry_count: usize,
    /// Sum of this layer's *own* file sizes - unlike `ImageJson::size_bytes`
    /// above, not deduped against the image's other layers (a per-layer
    /// breakdown wouldn't mean much deduped against its neighbors), so
    /// these can add up to more than the image's own total.
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct ImageDetailJson {
    pub id: String,
    pub repository: Option<String>,
    pub tag: Option<String>,
    pub env: Vec<(String, String)>,
    pub cmd: Option<String>,
    pub workdir: String,
    pub exposed_ports: Vec<(u16, String)>,
    /// Base-to-top, matching `Image::layers`' own order. There is no
    /// build *history* here (which Kilnfile instruction produced which
    /// layer) - kiln-image's format deliberately never records that (see
    /// layer.rs's "reproducibility by omission" docs: no instruction
    /// text, no timestamps, nothing that isn't actual file content/
    /// metadata) - so this is only ever the layer stack itself.
    pub layers: Vec<LayerDetailJson>,
    /// `true` iff this exact image content was pulled through a
    /// signature check that passed - never true for a locally built
    /// image or a Docker Hub pull (neither has a signature concept at
    /// all), and never true for a pull done with
    /// `--insecure-skip-verify` even if the image happened to be signed.
    pub signature_verified: bool,
}

pub fn inspect(store: &Store, id: &str) -> Response {
    let Ok(hash) = Hash::from_hex(id) else {
        return Response::text(400, format!("invalid image id: {id}"));
    };
    let Ok(img) = Image::load(store, &hash) else {
        return Response::text(404, "no such image");
    };

    let mut repository = None;
    let mut tag = None;
    for (r, t, tagged_id) in store.all_tags() {
        if tagged_id == hash {
            repository = Some(r);
            tag = Some(t);
            break;
        }
    }

    let layers = img
        .layers
        .iter()
        .map(|layer_id| {
            let manifest = LayerManifest::load(store, layer_id).ok();
            let entry_count = manifest.as_ref().map(|m| m.entries.len()).unwrap_or(0);
            let size_bytes = manifest
                .as_ref()
                .map(|m| {
                    m.entries
                        .iter()
                        .filter_map(|e| if let EntryKind::File { size, .. } = &e.kind { Some(*size) } else { None })
                        .sum()
                })
                .unwrap_or(0);
            LayerDetailJson {
                hash: layer_id.to_string(),
                entry_count,
                size_bytes,
            }
        })
        .collect();

    Response::json(
        200,
        &ImageDetailJson {
            id: hash.to_string(),
            repository,
            tag,
            env: img.config.env,
            cmd: img.config.cmd,
            workdir: img.config.workdir,
            exposed_ports: img.config.exposed_ports,
            layers,
            signature_verified: store.is_signature_verified(hash),
        },
    )
}

#[derive(Deserialize)]
pub struct PullRequest {
    pub reference: String,
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Blocks the request's own connection thread for the duration of the
/// pull (there's no progress-streaming here, just a plain response once
/// it's done or failed) - fine because `server.rs` gives every connection
/// its own thread, so a slow pull never blocks other endpoints (container
/// listing, stats polling, etc.) running on other connections meanwhile.
pub fn pull(store: &Store, req: &Request) -> Response {
    let body: PullRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    if body.reference.trim().is_empty() {
        return Response::text(400, "image reference must not be empty");
    }
    match registry::pull(store, &body.reference, body.insecure_skip_verify) {
        Ok(id) => Response::json(201, &serde_json::json!({ "id": id.to_string() })),
        Err(e) => Response::text(502, format!("{e}")),
    }
}

#[derive(Deserialize)]
pub struct PushRequest {
    /// Local image reference to push, e.g. `myapp:latest` or a bare id -
    /// pushed to the registry under this same name, exactly like `kiln
    /// push` itself.
    pub reference: String,
}

pub fn push(store: &Store, req: &Request) -> Response {
    let body: PushRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let image = match kiln_image::image::Image::resolve(store, &body.reference) {
        Ok(i) => i,
        Err(e) => return Response::text(404, format!("resolving {}: {e}", body.reference)),
    };
    let id = match image.save(store) {
        Ok(id) => id,
        Err(e) => return Response::text(500, format!("{e}")),
    };
    match registry::push(store, &id, &body.reference) {
        Ok(()) => Response::json(200, &serde_json::json!({ "id": id.to_string(), "pushed_as": body.reference })),
        Err(e) => Response::text(502, format!("push failed: {e}")),
    }
}

#[derive(Deserialize)]
pub struct TagRequest {
    /// Existing local reference (`name:tag` or a bare image id) to tag under a new name.
    pub source: String,
    /// New `name[:tag]` to point at the same image - see `kiln tag`'s own docs.
    pub target: String,
}

pub fn tag(store: &Store, req: &Request) -> Response {
    let body: TagRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let image = match kiln_image::image::Image::resolve(store, &body.source) {
        Ok(i) => i,
        Err(e) => return Response::text(404, format!("resolving {}: {e}", body.source)),
    };
    let id = match image.save(store) {
        Ok(id) => id,
        Err(e) => return Response::text(500, format!("{e}")),
    };
    match kiln_image::image::tag_reference(store, &id, &body.target) {
        Ok(()) => Response::json(200, &serde_json::json!({ "id": id.to_string(), "tagged_as": body.target })),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

#[derive(Deserialize)]
pub struct BuildRequest {
    /// Absolute path *inside kilnd's own filesystem* (i.e. WSL2, not a
    /// Windows path) - same "kilnd only knows its own side" pattern as
    /// volumes' host_path. The dashboard translates a Windows folder the
    /// user picked (via a native folder-select dialog) into its
    /// `/mnt/<drive>/...` WSL2-visible equivalent before sending this.
    pub context_dir: String,
    /// Relative to `context_dir`, defaults to `"Kilnfile"` - same as
    /// `kiln build -f`.
    #[serde(default)]
    pub kilnfile_path: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Serialize)]
pub struct BuildStepJson {
    pub instruction: String,
    pub cached: bool,
}

#[derive(Serialize)]
pub struct BuildResultJson {
    pub image_id: String,
    pub steps: Vec<BuildStepJson>,
    pub tagged: Option<String>,
}

/// Same connection-gets-its-own-thread reasoning as `pull` above applies
/// here too - a build can take a while (uncached RUN steps actually
/// execute), and this blocks only its own request.
pub fn build(store: &Store, req: &Request) -> Response {
    let body: BuildRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let context_dir = std::path::PathBuf::from(&body.context_dir);
    if !context_dir.is_dir() {
        return Response::text(400, format!("context directory not found: {}", body.context_dir));
    }
    let kilnfile_path = match &body.kilnfile_path {
        Some(p) => context_dir.join(p),
        None => context_dir.join("Kilnfile"),
    };
    let source = match std::fs::read_to_string(&kilnfile_path) {
        Ok(s) => s,
        Err(e) => return Response::text(400, format!("reading {}: {e}", kilnfile_path.display())),
    };

    let output = match kiln_image::build::build(store, &context_dir, &source) {
        Ok(o) => o,
        Err(e) => return Response::text(500, format!("build failed: {e}")),
    };

    let mut tagged = None;
    if let Some(tag) = &body.tag {
        let (name, tag_name) = kiln_image::image::split_name_tag(tag);
        let repo = kiln_image::image::normalize_repository(name);
        if let Err(e) = store.tag(&repo, tag_name, output.image_id) {
            return Response::text(500, format!("built {} but tagging failed: {e}", output.image_id));
        }
        tagged = Some(format!("{repo}:{tag_name}"));
    }

    Response::json(
        201,
        &BuildResultJson {
            image_id: output.image_id.to_string(),
            steps: output
                .steps
                .into_iter()
                .map(|s| BuildStepJson {
                    instruction: s.instruction,
                    cached: s.cached,
                })
                .collect(),
            tagged,
        },
    )
}

/// Serves the locally cached report from the last `kiln image scan`/`kiln
/// push --scan` for this image - never triggers a scan itself, so a plain
/// `GET` from the dashboard's image detail view can't accidentally kick
/// off a slow Trivy run.
pub fn get_scan(store: &Store, id: &str) -> Response {
    let Ok(hash) = Hash::from_hex(id) else {
        return Response::text(400, format!("invalid image id: {id}"));
    };
    match store.load_scan_report(hash) {
        Some(report) => Response::json(200, &report),
        None => Response::text(404, "no scan report for this image - scan it first"),
    }
}

/// Runs a real Trivy scan synchronously, same "this connection's own
/// thread blocks, nobody else's does" reasoning as `pull`/`build` above -
/// a scan can take a while on first run (Trivy downloading its
/// vulnerability database), same tradeoff.
pub fn post_scan(store: &Store, id: &str) -> Response {
    let Ok(hash) = Hash::from_hex(id) else {
        return Response::text(400, format!("invalid image id: {id}"));
    };
    let report = match kiln_image::scan::scan(store, &hash) {
        Ok(r) => r,
        Err(e) => return Response::text(500, format!("{e}")),
    };
    if let Err(e) = store.save_scan_report(hash, &report) {
        return Response::text(500, format!("scan succeeded but saving the report failed: {e}"));
    }
    Response::json(201, &report)
}

pub fn remove(store: &Store, id: &str) -> Response {
    let Ok(hash) = Hash::from_hex(id) else {
        return Response::text(400, format!("invalid image id: {id}"));
    };
    match kiln_cli::commands::rmi::remove_by_id(store, hash) {
        Ok(message) => Response::json(200, &serde_json::json!({ "message": message })),
        Err(e) => Response::text(404, e),
    }
}
