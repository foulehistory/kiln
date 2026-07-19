//! Store-wide disk usage and garbage collection - `GET /disk-usage` and
//! `POST /gc`, the HTTP counterparts of `kiln gc`'s reporting (there's no
//! existing CLI equivalent of `disk_usage` itself; it's assembled here
//! straight from the store's own directory layout, the same directories
//! `kiln-image::store::Store` already owns).

use kilnd_core::http::Response;
use kiln_cli::commands::gc::collect_garbage;
use kiln_image::store::Store;
use serde::Serialize;

#[derive(Serialize)]
pub struct DiskUsageJson {
    /// Content-addressed file content - shared across every layer/image
    /// that references it (see `kiln-image::store`'s dedup docs), so this
    /// is usually the biggest number and the one `gc` actually shrinks.
    pub blobs_bytes: u64,
    /// Layer manifests and their materialized directories - not touched
    /// by `gc` (see `commands::gc`'s module docs on why).
    pub layers_bytes: u64,
    pub volumes_bytes: u64,
    pub containers_bytes: u64,
    pub total_bytes: u64,
}

pub fn disk_usage(store: &Store) -> Response {
    let blobs_bytes = super::dir_size(&store.root().join("blobs"));
    let layers_bytes = super::dir_size(&store.root().join("layers"));
    let volumes_bytes = super::dir_size(&store.root().join("volumes"));
    let containers_bytes = super::dir_size(&store.root().join("containers"));
    Response::json(
        200,
        &DiskUsageJson {
            blobs_bytes,
            layers_bytes,
            volumes_bytes,
            containers_bytes,
            total_bytes: blobs_bytes + layers_bytes + volumes_bytes + containers_bytes,
        },
    )
}

#[derive(Serialize)]
pub struct GcResultJson {
    pub blobs_removed: u64,
    pub bytes_freed: u64,
    pub images_removed: u64,
}

pub fn gc(store: &Store) -> Response {
    let summary = collect_garbage(store);
    Response::json(
        200,
        &GcResultJson { blobs_removed: summary.blobs_removed, bytes_freed: summary.bytes_freed, images_removed: summary.images_removed },
    )
}
