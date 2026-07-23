//! `kilnd`'s API surface over `kiln_image::secrets` - list/create/delete
//! by name only. There is deliberately no "get" endpoint: a secret's
//! value, once created, is never readable again through this API (or any
//! other Kiln surface) - the same one-way property a real password
//! manager's "create" flow has.

use kiln_image::store::Store;
use kilnd_core::http::{Request, Response};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SecretJson {
    pub name: String,
    /// `None` for a secret created before the metadata sidecar existed
    /// and never since rotated - see `kiln_image::secrets::meta`'s own
    /// docs.
    #[serde(flatten)]
    pub meta: Option<kiln_image::secrets::SecretMeta>,
}

pub fn list(store: &Store) -> Response {
    let out: Vec<SecretJson> = kiln_image::secrets::list(store.root())
        .into_iter()
        .map(|name| {
            let meta = kiln_image::secrets::meta(store.root(), &name);
            SecretJson { name, meta }
        })
        .collect();
    Response::json(200, &out)
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub name: String,
    pub value: String,
    /// See `kiln_image::secrets::SecretMeta::ttl_secs`'s own docs -
    /// informative only.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

pub fn create(store: &Store, req: &Request) -> Response {
    let body: CreateRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    if body.name.trim().is_empty() {
        return Response::text(400, "secret name must not be empty");
    }
    if body.value.is_empty() {
        return Response::text(400, "secret value must not be empty");
    }
    match kiln_image::secrets::create(store.root(), &body.name, body.value.as_bytes(), body.ttl_secs) {
        Ok(()) => Response::json(201, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

pub fn remove(store: &Store, name: &str) -> Response {
    match kiln_image::secrets::remove(store.root(), name) {
        Ok(()) => Response::json(200, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(404, format!("{e}")),
    }
}

#[derive(Deserialize)]
pub struct RotateRequest {
    /// Omitted (or `null`) means "generate a random value" - the
    /// dashboard's "Rotate" button doesn't ask an operator to type a new
    /// value up front, so it never sends this field.
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Serialize)]
pub struct RotateResponse {
    pub meta: kiln_image::secrets::SecretMeta,
    /// Only present when the server generated the new value (no `value`
    /// in the request) - the one and only time it's ever shown, since
    /// there is no "get" endpoint for a secret's value (see this module's
    /// own docs). A caller that supplied its own `value` already knows
    /// it, so echoing it back here would just be a needless second
    /// place the plaintext travels through.
    pub generated_value: Option<String>,
    /// Container ids/names this secret is mounted in and running right
    /// now, and whether each one's live `/run/secrets/<name>` tmpfs file
    /// was actually updated in place - see
    /// `kiln_cli::commands::secret::update_live_secret_mounts`'s own
    /// docs on why this can't be guaranteed for every container.
    pub live_updates: Vec<LiveUpdateJson>,
}

#[derive(Serialize)]
pub struct LiveUpdateJson {
    pub container_id: String,
    pub container_name: String,
    pub updated: bool,
}

pub fn rotate(store: &Store, name: &str, req: &Request) -> Response {
    let body: RotateRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let (new_value, generated_value) = match body.value {
        Some(v) if !v.is_empty() => (v.into_bytes(), None),
        _ => {
            let generated = kiln_cli::commands::secret::generate_value();
            (generated.clone().into_bytes(), Some(generated))
        }
    };
    let meta = match kiln_image::secrets::rotate(store.root(), name, &new_value) {
        Ok(m) => m,
        Err(e) => return Response::text(if e.kind() == std::io::ErrorKind::NotFound { 404 } else { 500 }, format!("{e}")),
    };
    let live_updates = kiln_cli::commands::secret::update_live_secret_mounts(store, name, &new_value)
        .into_iter()
        .map(|u| LiveUpdateJson {
            container_id: u.container_id,
            container_name: u.container_name,
            updated: u.updated,
        })
        .collect();
    Response::json(
        200,
        &RotateResponse {
            meta,
            generated_value,
            live_updates,
        },
    )
}
