//! `kilnd`'s API surface over `kiln_image::secrets` - list/create/delete
//! by name only. There is deliberately no "get" endpoint: a secret's
//! value, once created, is never readable again through this API (or any
//! other Kiln surface) - the same one-way property a real password
//! manager's "create" flow has.

use kilnd_core::http::{Request, Response};
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SecretJson {
    pub name: String,
}

pub fn list(store: &Store) -> Response {
    let out: Vec<SecretJson> = kiln_image::secrets::list(store.root()).into_iter().map(|name| SecretJson { name }).collect();
    Response::json(200, &out)
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub name: String,
    pub value: String,
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
    match kiln_image::secrets::create(store.root(), &body.name, body.value.as_bytes()) {
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
