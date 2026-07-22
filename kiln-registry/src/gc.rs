//! `kiln-registry gc` - orphaned-blob garbage collection, mirroring the
//! mark-and-sweep reasoning in `kiln gc` (the main runtime's own local
//! store GC, `kiln-cli/src/commands/gc.rs`) but simpler here: this
//! store has no layer-manifest indirection to walk through and no
//! "untagged image" concept of its own to separately sweep - every
//! manifest this server stores is already tag-addressed, so the mark
//! phase is a single-level "which blob digests does some stored
//! manifest's `config`/`layers` reference" pass, and the sweep is just
//! `blobs/sha256/*` entries not in that set.

use crate::store::RegistryStore;
use serde::Deserialize;
use std::collections::HashSet;

/// Just enough of an OCI image manifest to find the blob digests it
/// references - unknown fields (`schemaVersion`, `mediaType`, ...) are
/// ignored by `serde_json` by default, so this doesn't need to track the
/// full manifest schema `kiln-image`'s own (private) `OciManifest`
/// already models more completely elsewhere.
#[derive(Deserialize)]
struct ManifestDigests {
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GcSummary {
    pub blobs_removed: u64,
    pub bytes_freed: u64,
}

/// `dry_run: true` computes and reports exactly what a real run would
/// remove, without deleting anything - a safety net worth having here
/// specifically because a shared, multi-tenant registry's blobs are
/// costlier to lose by mistake than a single local dev store's.
pub fn collect_garbage(store: &RegistryStore, dry_run: bool) -> GcSummary {
    let mut live_blobs: HashSet<String> = HashSet::new();
    for bytes in store.all_manifest_bytes() {
        let Ok(manifest) = serde_json::from_slice::<ManifestDigests>(&bytes) else {
            continue;
        };
        if let Some(config) = manifest.config {
            live_blobs.insert(config.digest);
        }
        for layer in manifest.layers {
            live_blobs.insert(layer.digest);
        }
    }

    let mut summary = GcSummary::default();
    for hex in store.all_blob_hex() {
        let digest = format!("sha256:{hex}");
        if live_blobs.contains(&digest) {
            continue;
        }
        if let Some(size) = store.blob_size(&digest) {
            summary.bytes_freed += size;
        }
        if dry_run {
            summary.blobs_removed += 1;
            continue;
        }
        if store.remove_blob(&digest).is_ok() {
            summary.blobs_removed += 1;
        }
    }
    summary
}
