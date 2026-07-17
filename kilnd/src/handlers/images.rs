use crate::http::Response;
use kiln_image::image::Image;
use kiln_image::layer::{EntryKind, LayerManifest};
use kiln_image::store::{Hash, Store};
use serde::Serialize;
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
