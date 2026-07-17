//! `kiln rmi` - untag (or, given a bare content hash, delete the image
//! manifest for) one or more images.
//!
//! This deliberately does **not** touch the blob store: because blobs are
//! shared across every layer/image that references them (see
//! `kiln-image::store`'s dedup docs), safely deleting a blob requires
//! knowing nothing else still points to it - a proper mark-and-sweep GC,
//! which doesn't exist yet. `rmi` only ever removes the small JSON
//! pointers (tags, image manifests); disk space used by layer content is
//! reclaimed by a future `kiln gc`, not by this command.

use crate::error::CliResult;
use kiln_image::image::{normalize_repository, split_name_tag};
use kiln_image::store::{Hash, Store};

#[derive(clap::Args, Debug)]
pub struct Args {
    pub images: Vec<String>,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    for reference in &args.images {
        let (name, tag) = split_name_tag(reference);
        let repo = normalize_repository(name);
        let tag_path = store.refs_dir().join(&repo).join(tag);

        if tag_path.is_file() {
            match std::fs::remove_file(&tag_path) {
                Ok(()) => println!("untagged: {repo}:{tag}"),
                Err(e) => eprintln!("kiln: untagging {repo}:{tag}: {e}"),
            }
            continue;
        }

        if let Ok(hash) = Hash::from_hex(reference) {
            let path = store.images_dir().join(format!("{hash}.json"));
            if path.is_file() {
                match std::fs::remove_file(&path) {
                    Ok(()) => println!("deleted: {hash}"),
                    Err(e) => eprintln!("kiln: deleting {hash}: {e}"),
                }
                continue;
            }
        }

        eprintln!("kiln: no such image: {reference}");
    }
    Ok(())
}

/// Remove an image identified by its content hash: untags every tag that
/// currently points at it (there can be more than one, unlike the
/// single-reference case [`run`] handles) and deletes the manifest
/// itself. Used by kilnd's `DELETE /images/:id` - the dashboard only ever
/// has the hash to act on, not a specific `repo:tag` the way `kiln rmi`
/// does, so "remove everything pointing at this id" is the only
/// unambiguous meaning of "remove this image" there.
pub fn remove_by_id(store: &Store, id: Hash) -> Result<String, String> {
    let mut removed_tags = Vec::new();
    for (repo, tag, tagged_id) in store.all_tags() {
        if tagged_id == id {
            let tag_path = store.refs_dir().join(&repo).join(&tag);
            std::fs::remove_file(&tag_path).map_err(|e| format!("untagging {repo}:{tag}: {e}"))?;
            removed_tags.push(format!("{repo}:{tag}"));
        }
    }

    let manifest_path = store.images_dir().join(format!("{id}.json"));
    let manifest_existed = manifest_path.is_file();
    if manifest_existed {
        std::fs::remove_file(&manifest_path).map_err(|e| format!("deleting {id}: {e}"))?;
    } else if removed_tags.is_empty() {
        return Err(format!("no such image: {id}"));
    }

    if removed_tags.is_empty() {
        Ok(format!("deleted: {id}"))
    } else {
        Ok(format!("untagged {} and deleted: {id}", removed_tags.join(", ")))
    }
}
