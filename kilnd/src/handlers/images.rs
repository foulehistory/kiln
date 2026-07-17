use crate::http::Response;
use kiln_image::image::Image;
use kiln_image::layer::{EntryKind, LayerManifest};
use kiln_image::store::{Hash, Store};
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

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

/// Walk `refs_dir()` to find every `<repository>/<tag>` ref, however deep
/// `<repository>` itself is. It's not always one segment: unqualified
/// names get normalized to `library/<name>` (see
/// `kiln_image::image::normalize_repository`), and a user-supplied name
/// can already contain its own `/`. Only the last path component is ever
/// a tag - everything above it, however many segments, is the repository.
fn walk_refs(dir: &Path, repo_prefix: &str, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if file_type.is_dir() {
            let prefix = if repo_prefix.is_empty() { name } else { format!("{repo_prefix}/{name}") };
            walk_refs(&entry.path(), &prefix, out);
        } else {
            out.push((repo_prefix.to_string(), name));
        }
    }
}

pub fn list(store: &Store) -> Response {
    let mut refs = Vec::new();
    walk_refs(&store.refs_dir(), "", &mut refs);
    let tagged: Vec<(String, String, Hash)> = refs
        .into_iter()
        .filter_map(|(repo_name, tag_name)| {
            let id = store.resolve_tag(&repo_name, &tag_name).ok()?;
            Some((repo_name, tag_name, id))
        })
        .collect();

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (repo, tag, id) in tagged {
        seen.insert(id);
        out.push(image_json(store, id, Some(repo), Some(tag)));
    }

    if let Ok(entries) = std::fs::read_dir(store.images_dir()) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            let Some(hex) = name.strip_suffix(".json") else { continue };
            let Ok(id) = Hash::from_hex(hex) else { continue };
            if !seen.contains(&id) {
                out.push(image_json(store, id, None, None));
            }
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
