//! Surfaces `kiln-compose up`'s transient "waiting for a dependency's
//! healthcheck" state to the dashboard - a one-shot `kiln-compose up`
//! process has no other way to expose that to `kilnd`/the dashboard,
//! both different processes, than a marker file on the shared store (see
//! `kiln_compose::main::WaitingMarker`). Best-effort/informational only:
//! a `kiln-compose up` killed outright (not a graceful failure) can leave
//! a stale marker behind until the next `up` either resolves or
//! overwrites it - acceptable for a purely cosmetic indicator, not
//! anything load-bearing.

use kiln_image::store::Store;
use kilnd_core::http::Response;
use serde::Serialize;

#[derive(Serialize)]
pub struct ComposeWaitingJson {
    /// `<project>_<service>` - the exact name the container will have
    /// once created, matching every other container-naming convention in
    /// this project.
    pub container_name: String,
    pub waiting_for: String,
}

pub fn list(store: &Store) -> Response {
    let dir = store.root().join("compose-waiting");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Response::json(200, &Vec::<ComposeWaitingJson>::new());
    };
    let out: Vec<ComposeWaitingJson> = entries
        .flatten()
        .filter_map(|e| {
            let container_name = e.file_name().to_str()?.to_string();
            let waiting_for = std::fs::read_to_string(e.path()).ok()?;
            Some(ComposeWaitingJson { container_name, waiting_for })
        })
        .collect();
    Response::json(200, &out)
}
