//! Thin HTTP client for dispatching a compose service to a remote node's
//! `kilnd` (see `kiln-cli/src/commands/node.rs` for the node registry
//! this reads from, and `kilnd/src/server.rs` for the authenticated
//! remote listener this talks to). `kilnd` is a bin-only crate (no lib
//! target `kiln-compose` could depend on for its request/response
//! types), so this is a small, deliberately narrow re-declaration of
//! just the JSON shapes `kiln-compose` actually needs - not a shared
//! type, just the same wire format by convention.

use kiln_cli::commands::node::Node;
use kiln_cli::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct RunRequest {
    image: String,
    command: Vec<String>,
    name: Option<String>,
    volumes: Vec<String>,
    network: Option<String>,
    environment: Vec<(String, String)>,
    ports: Vec<String>,
    secrets: Vec<String>,
}

#[derive(Deserialize, Clone)]
pub struct RemoteContainer {
    pub id: String,
    pub status: String,
}

fn url(node: &Node, path: &str) -> String {
    format!("http://{}{}", node.address, path)
}

pub struct RunArgs {
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub volumes: Vec<String>,
    pub network: Option<String>,
    pub environment: Vec<(String, String)>,
    pub ports: Vec<String>,
    pub secrets: Vec<String>,
}

/// Creates a container on `node` - the remote-dispatch equivalent of
/// `kiln_cli::commands::run::start` for a local service. Fails the same
/// way a local start failing would: `cmd_up` propagates the error and
/// aborts the rest of `up`, rather than silently skipping the service.
pub fn create_container(node: &Node, args: RunArgs) -> CliResult<RemoteContainer> {
    let body = RunRequest {
        image: args.image,
        command: args.command,
        name: Some(args.name.clone()),
        volumes: args.volumes,
        network: args.network,
        environment: args.environment,
        ports: args.ports,
        secrets: args.secrets,
    };
    let resp = ureq::post(&url(node, "/containers"))
        .set("Authorization", &format!("Bearer {}", node.token))
        .send_json(serde_json::to_value(&body).map_err(|e| CliError::msg(e.to_string()))?)
        .map_err(|e| CliError::msg(format!("creating {} on node {}: {e}", args.name, node.name)))?;
    resp.into_json().map_err(|e| CliError::msg(format!("parsing response from node {}: {e}", node.name)))
}

/// `None` on any failure (unreachable node, container doesn't exist,
/// anything else) - callers (`cmd_ps`) treat that as "unknown", not a
/// hard error, since one unreachable node shouldn't stop the rest of
/// `ps` from reporting on everything else.
pub fn get_container(node: &Node, name: &str) -> Option<RemoteContainer> {
    ureq::get(&url(node, &format!("/containers/{name}")))
        .set("Authorization", &format!("Bearer {}", node.token))
        .call()
        .ok()?
        .into_json()
        .ok()
}

/// Best-effort, like `cmd_down`'s local removal loop (which also just
/// `eprintln!`s and moves on rather than aborting the rest of `down`) -
/// a container already gone on the remote node, or the node being
/// unreachable at teardown time, shouldn't block removing everything
/// else `down` is responsible for.
pub fn remove_container(node: &Node, name: &str) -> Result<(), String> {
    ureq::delete(&url(node, &format!("/containers/{name}")))
        .set("Authorization", &format!("Bearer {}", node.token))
        .call()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Best-effort, idempotent network provisioning on `node` - mirrors
/// `cmd_up`'s own local `if NetworkConfig::load(...).is_none() { create
/// }` check, except there's no cheap way to ask a remote kilnd "does
/// this network already exist" other than trying to create it and
/// tolerating the "already exists" failure. Any other failure here is
/// swallowed too: if the network genuinely isn't usable, the container
/// creation call right after this one will surface a much clearer error
/// than guessing at kilnd's error text would.
pub fn ensure_remote_network(node: &Node, name: &str, subnet: &str) {
    let _ = ureq::post(&url(node, "/networks"))
        .set("Authorization", &format!("Bearer {}", node.token))
        .send_json(serde_json::json!({ "name": name, "subnet": subnet }));
}

/// Best-effort teardown counterpart to `ensure_remote_network` - errors
/// (network already gone, node unreachable) are the caller's problem to
/// report, not this function's to retry.
pub fn remove_network(node: &Node, name: &str) -> Result<(), String> {
    ureq::delete(&url(node, &format!("/networks/{name}")))
        .set("Authorization", &format!("Bearer {}", node.token))
        .call()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Non-follow only - unlike `stream_aggregated_logs`'s local tailing,
/// following a remote node's logs would need its own long-lived
/// connection/thread per node; deferred rather than half-implemented for
/// this first pass (see this crate's own docs on the multi-host MVP's
/// deliberately narrow scope).
pub fn logs(node: &Node, name: &str) -> CliResult<String> {
    let resp = ureq::get(&url(node, &format!("/containers/{name}/logs")))
        .set("Authorization", &format!("Bearer {}", node.token))
        .call()
        .map_err(|e| CliError::msg(format!("fetching logs from node {}: {e}", node.name)))?;
    resp.into_string().map_err(|e| CliError::msg(e.to_string()))
}
