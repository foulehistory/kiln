//! `kiln gc` - reclaim disk space `kiln rmi` deliberately doesn't: removing
//! a tag never touches the blobs a layer's files live in (they may be
//! shared with other images/layers - see `kiln-image::store`'s dedup
//! docs), so blobs and whole images just accumulate. This is the
//! mark-and-sweep that actually frees them: mark every blob reachable
//! from a still-tagged image, sweep everything else.
//!
//! Deliberately conservative: only blobs and untagged (`<none>`) image
//! manifests are removed. Layer manifests and their materialized
//! directories under `layers/` are left alone even when no tagged image
//! references them, since an untagged image (e.g. one only ever run by
//! raw content hash) could still have a live container using one as an
//! overlayfs lowerdir - safe to revisit once there's a way to know that
//! for certain.

use crate::error::CliResult;
use kiln_image::image::Image;
use kiln_image::layer::{EntryKind, LayerManifest};
use kiln_image::store::Store;
use std::collections::HashSet;

#[derive(clap::Args, Debug)]
pub struct Args {}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GcSummary {
    pub blobs_removed: u64,
    pub bytes_freed: u64,
    pub images_removed: u64,
}

pub fn run(store: &Store, _args: Args) -> CliResult {
    let summary = collect_garbage(store);
    println!(
        "removed {} blob{} ({}), {} untagged image{}",
        summary.blobs_removed,
        if summary.blobs_removed == 1 { "" } else { "s" },
        format_bytes(summary.bytes_freed),
        summary.images_removed,
        if summary.images_removed == 1 { "" } else { "s" },
    );
    Ok(())
}

/// The actual mark-and-sweep, factored out from [`run`] so it's testable
/// without going through stdout: mark every blob reachable from a
/// still-tagged image, then delete every on-disk blob and untagged image
/// manifest that isn't in that marked set.
pub fn collect_garbage(store: &Store) -> GcSummary {
    let tagged_ids: HashSet<_> = store.all_tags().into_iter().map(|(_, _, id)| id).collect();

    let mut live_blobs = HashSet::new();
    for id in &tagged_ids {
        let Ok(image) = Image::load(store, id) else { continue };
        for layer_id in &image.layers {
            let Ok(manifest) = LayerManifest::load(store, layer_id) else { continue };
            for entry in &manifest.entries {
                if let EntryKind::File { blob, .. } = &entry.kind {
                    live_blobs.insert(*blob);
                }
            }
        }
    }

    let mut summary = GcSummary::default();
    for hash in store.all_blobs() {
        if live_blobs.contains(&hash) {
            continue;
        }
        if let Some(size) = store.blob_size(&hash) {
            summary.bytes_freed += size;
        }
        if store.remove_blob(&hash).is_ok() {
            summary.blobs_removed += 1;
        }
    }

    for id in store.all_image_ids() {
        if tagged_ids.contains(&id) {
            continue;
        }
        if store.remove_image(&id).is_ok() {
            summary.images_removed += 1;
        }
    }

    summary
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}
