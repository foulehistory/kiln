use crate::http::{Request, Response};
use kiln_cli::commands::volume;
use kiln_cli::container::Container;
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct VolumeJson {
    pub name: String,
    /// Names of containers whose stored `-v` specs reference this volume -
    /// same matching `volume::run`'s `Prune` uses to decide what's safe to
    /// delete, surfaced here so the dashboard can do the same "in use, so
    /// disable Remove" check `NetworksView` already does for networks.
    pub containers: Vec<String>,
    /// Total size of every file under the volume - deliberately not
    /// deduped/cached like the image store's blobs (`images::image_json`)
    /// since a volume is just a plain directory a container writes to
    /// directly, not content-addressed storage.
    pub size_bytes: u64,
    /// Absolute path *inside kilnd's own filesystem* (i.e. inside WSL2,
    /// not a Windows path) - the dashboard's Electron main process
    /// translates this into a `\\wsl.localhost\<distro>\...` UNC path to
    /// open it in Explorer, since kilnd has no notion of "the Windows
    /// side" at all.
    pub host_path: String,
}

fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else { return 0 };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += meta.len();
        }
    }
    total
}

pub fn list(store: &Store) -> Response {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(volume::volumes_dir(store)) else {
        return Response::json(200, &out);
    };

    let all_containers = Container::list(store);
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let containers: Vec<String> = all_containers
            .iter()
            .filter(|c| c.volumes.iter().any(|v| v.split_once(':').map(|(n, _)| n) == Some(name.as_str())))
            .map(|c| c.name.clone())
            .collect();
        let path = entry.path();
        let size_bytes = dir_size(&path);
        let host_path = path.to_string_lossy().into_owned();
        out.push(VolumeJson { name, containers, size_bytes, host_path });
    }

    Response::json(200, &out)
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub name: String,
}

pub fn create(store: &Store, req: &Request) -> Response {
    let body: CreateRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    if body.name.trim().is_empty() {
        return Response::text(400, "volume name must not be empty");
    }
    match volume::run(store, volume::Command::Create { name: body.name }) {
        Ok(()) => Response::json(201, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

pub fn remove(store: &Store, name: &str) -> Response {
    match volume::run(store, volume::Command::Rm { name: name.to_string() }) {
        Ok(()) => Response::json(200, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(404, format!("{e}")),
    }
}
