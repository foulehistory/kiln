use crate::error::CliResult;
use kiln_image::image::Image;
use kiln_image::store::{Hash, Store};
use std::collections::HashSet;
use std::path::Path;

#[derive(clap::Args, Debug)]
pub struct Args {}

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

pub fn run(store: &Store, _args: Args) -> CliResult {
    println!("{:<32}{:<12}{:<66}LAYERS", "REPOSITORY", "TAG", "IMAGE ID");

    let mut seen = HashSet::new();
    let mut refs = Vec::new();
    walk_refs(&store.refs_dir(), "", &mut refs);
    for (repo_name, tag_name) in refs {
        let Ok(id) = store.resolve_tag(&repo_name, &tag_name) else { continue };
        seen.insert(id);
        let layers = Image::load(store, &id).map(|i| i.layers.len()).unwrap_or(0);
        println!("{repo_name:<32}{tag_name:<12}{id:<66}{layers}");
    }

    if let Ok(entries) = std::fs::read_dir(store.images_dir()) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            let Some(hex) = name.strip_suffix(".json") else { continue };
            let Ok(id) = Hash::from_hex(hex) else { continue };
            if seen.contains(&id) {
                continue;
            }
            let layers = Image::load(store, &id).map(|i| i.layers.len()).unwrap_or(0);
            println!("{:<32}{:<12}{id:<66}{layers}", "<none>", "<none>");
        }
    }

    Ok(())
}
