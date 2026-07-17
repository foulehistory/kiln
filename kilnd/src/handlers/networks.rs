use crate::http::{Request, Response};
use kiln_cli::commands::network::{self, NetworkConfig};
use kiln_cli::container::Container;
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct NetworkJson {
    pub name: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    pub containers: Vec<NetworkContainerJson>,
}

#[derive(Serialize)]
pub struct NetworkContainerJson {
    pub id: String,
    pub name: String,
    pub ip: String,
}

pub fn list(store: &Store) -> Response {
    let mut out = Vec::new();
    let networks_dir = store.root().join("networks");

    let Ok(entries) = std::fs::read_dir(&networks_dir) else {
        return Response::json(200, &out);
    };

    let all_containers = Container::list(store);

    for entry in entries.flatten() {
        let Some(stem) = entry.path().file_stem().map(|s| s.to_string_lossy().into_owned()) else { continue };
        let Some(cfg) = NetworkConfig::load(store, &stem) else { continue };

        let containers: Vec<NetworkContainerJson> = all_containers
            .iter()
            .filter(|c| c.network.as_deref() == Some(cfg.name.as_str()))
            .filter_map(|c| c.ip.clone().map(|ip| NetworkContainerJson { id: c.id.clone(), name: c.name.clone(), ip }))
            .collect();

        out.push(NetworkJson { name: cfg.name, bridge: cfg.bridge, subnet: cfg.subnet, gateway: cfg.gateway, containers });
    }

    Response::json(200, &out)
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default)]
    pub subnet: Option<String>,
}

pub fn create(store: &Store, req: &Request) -> Response {
    let body: CreateRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    // Same default the CLI's `#[arg(long, default_value = "172.30.0.0/24")]`
    // uses, so a dashboard-created network without an explicit subnet
    // behaves identically to `kiln network create <name>`.
    let subnet = body.subnet.unwrap_or_else(|| "172.30.0.0/24".to_string());
    match network::run(store, network::Command::Create { name: body.name, subnet }) {
        Ok(()) => Response::json(201, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

pub fn remove(store: &Store, name: &str) -> Response {
    match network::run(store, network::Command::Rm { name: name.to_string() }) {
        Ok(()) => Response::json(200, &serde_json::json!({ "ok": true })),
        Err(e) => Response::text(404, format!("{e}")),
    }
}
