//! `kiln node` - a local registry of remote `kilnd` instances this
//! machine can dispatch `kiln-compose up`'s `node:`-tagged services to.
//! Purely local bookkeeping (a JSON file under the store) - there is no
//! discovery, no central control plane, no consensus: each node is
//! reached directly by address, and each remains independently
//! responsible for its own containers, images, and store. See
//! `kilnd/src/server.rs`'s own docs on the remote listener a node must
//! have enabled for this to reach it at all.

use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    /// `host:port` of that node's `kilnd` *remote* listener - not its
    /// default loopback port, which by definition isn't reachable from
    /// here. e.g. `192.168.1.50:7868`.
    pub address: String,
    pub token: String,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Register a remote node. `kilnd` must already be running there
    /// with `KILN_REMOTE_TOKEN` set to the same value passed here via
    /// `--token`, and `address` must be its remote listener's
    /// `host:port` (see kilnd's own docs - not its default port).
    Add {
        name: String,
        address: String,
        #[arg(long)]
        token: String,
    },
    /// List registered nodes and whether each is currently reachable.
    Ls,
    Rm {
        name: String,
    },
}

fn nodes_path(store: &Store) -> PathBuf {
    store.root().join("nodes.json")
}

pub fn load_nodes(store: &Store) -> Vec<Node> {
    std::fs::read(nodes_path(store)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_nodes(store: &Store, nodes: &[Node]) -> CliResult {
    let json = serde_json::to_vec_pretty(nodes).expect("Node serialization cannot fail");
    std::fs::write(nodes_path(store), json).map_err(|e| CliError::msg(format!("writing nodes.json: {e}")))
}

pub fn find_node(store: &Store, name: &str) -> Option<Node> {
    load_nodes(store).into_iter().find(|n| n.name == name)
}

/// A quick reachability probe - `GET /version` with the node's own
/// token, same request `kiln-compose` itself would need to succeed
/// before dispatching anything real there. Also used by `kilnd`'s own
/// `GET /nodes` handler for the dashboard's Nodes view.
pub fn ping(node: &Node) -> bool {
    let url = format!("http://{}/version", node.address);
    ureq::get(&url).set("Authorization", &format!("Bearer {}", node.token)).timeout(std::time::Duration::from_secs(2)).call().is_ok()
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Add { name, address, token } => {
            let mut nodes = load_nodes(store);
            if nodes.iter().any(|n| n.name == name) {
                return Err(CliError::msg(format!("node {name} already exists - remove it first to change its address/token")));
            }
            nodes.push(Node { name: name.clone(), address, token });
            save_nodes(store, &nodes)?;
            println!("{name}");
        }
        Command::Ls => {
            println!("{:<20}{:<24}REACHABLE", "NAME", "ADDRESS");
            for n in load_nodes(store) {
                let reachable = if ping(&n) { "yes" } else { "no" };
                println!("{:<20}{:<24}{reachable}", n.name, n.address);
            }
        }
        Command::Rm { name } => {
            let mut nodes = load_nodes(store);
            let before = nodes.len();
            nodes.retain(|n| n.name != name);
            if nodes.len() == before {
                return Err(CliError::msg(format!("no such node: {name}")));
            }
            save_nodes(store, &nodes)?;
            println!("{name}");
        }
    }
    Ok(())
}
