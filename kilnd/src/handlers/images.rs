use crate::http::{Request, Response};
use kiln_image::image::Image;
use kiln_image::layer::{EntryKind, LayerManifest};
use kiln_image::registry;
use kiln_image::store::{Hash, Store};
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

    ImageJson { id: id.to_string(), repository, tag, layers, size_bytes }
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
                .map(|m| m.entries.iter().filter_map(|e| if let EntryKind::File { size, .. } = &e.kind { Some(*size) } else { None }).sum())
                .unwrap_or(0);
            LayerDetailJson { hash: layer_id.to_string(), entry_count, size_bytes }
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
        },
    )
}

#[derive(Deserialize)]
pub struct PullRequest {
    pub reference: String,
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
    match registry::pull(store, &body.reference) {
        Ok(id) => Response::json(201, &serde_json::json!({ "id": id.to_string() })),
        Err(e) => Response::text(502, format!("{e}")),
    }
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
