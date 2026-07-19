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
        let size_bytes = crate::handlers::dir_size(&path);
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

pub fn export(store: &Store, name: &str) -> Response {
    match volume::export_bytes(store, name) {
        Ok(bytes) => Response {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/gzip".into()),
                ("Content-Disposition".into(), format!("attachment; filename=\"{name}.tar.gz\"")),
            ],
            body: bytes,
        },
        Err(e) => Response::text(404, format!("{e}")),
    }
}

pub fn import(store: &Store, name: &str, req: &Request) -> Response {
    if name.trim().is_empty() {
        return Response::text(400, "volume name must not be empty");
    }
    match volume::import_bytes(store, name, &req.body) {
        Ok(()) => Response::json(201, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(400, format!("{e}")),
    }
}

/// Resolves a `?path=` query param (a path *relative to the volume
/// root*) into a real filesystem path, refusing anything that would
/// escape the volume: `..` components are rejected outright, and - since
/// a volume's contents come from whatever a container wrote there, which
/// could include a symlink - the final resolved path is canonicalized
/// and checked to still be inside the volume, catching a symlink escape
/// a plain `..` check alone wouldn't.
fn resolve_within_volume(store: &Store, volume_name: &str, rel_path: &str) -> Option<std::path::PathBuf> {
    let base = volume::path(store, volume_name);
    if !base.is_dir() {
        return None;
    }
    let mut resolved = base.clone();
    for component in rel_path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return None;
        }
        resolved.push(component);
    }
    if resolved.exists() {
        let base_canon = base.canonicalize().ok()?;
        let resolved_canon = resolved.canonicalize().ok()?;
        if !resolved_canon.starts_with(&base_canon) {
            return None;
        }
    }
    Some(resolved)
}

#[derive(Serialize)]
pub struct FileEntryJson {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

pub fn list_files(store: &Store, name: &str, req: &Request) -> Response {
    let rel = req.query.get("path").map(String::as_str).unwrap_or("");
    let Some(dir) = resolve_within_volume(store, name, rel) else {
        return Response::text(400, "invalid path");
    };
    if !dir.is_dir() {
        return Response::text(404, "not a directory");
    }
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            out.push(FileEntryJson {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size_bytes: if meta.is_dir() { 0 } else { meta.len() },
            });
        }
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    Response::json(200, &out)
}

/// A preview, not a download: capped well below anything that would be
/// awkward to render inline, and only for content that's actually valid
/// UTF-8 text (binary files are reported as such rather than dumped).
const MAX_PREVIEW_BYTES: u64 = 256 * 1024;

pub fn read_file(store: &Store, name: &str, req: &Request) -> Response {
    let rel = req.query.get("path").map(String::as_str).unwrap_or("");
    let Some(path) = resolve_within_volume(store, name, rel) else {
        return Response::text(400, "invalid path");
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return Response::text(404, "not found");
    };
    if !meta.is_file() {
        return Response::text(404, "not a file");
    }
    if meta.len() > MAX_PREVIEW_BYTES {
        return Response::text(413, format!("file too large to preview (>{} KiB)", MAX_PREVIEW_BYTES / 1024));
    }
    match std::fs::read(&path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Response::text(200, text),
            Err(_) => Response::text(415, "binary file - not previewable"),
        },
        Err(e) => Response::text(500, format!("{e}")),
    }
}
