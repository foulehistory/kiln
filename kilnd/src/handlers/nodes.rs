//! `GET /nodes` - the dashboard's read-only Nodes view. Reads the same
//! local registry `kiln node add`/`ls`/`rm` manage
//! (`kiln_cli::commands::node`) - node *management* stays CLI-only for
//! now, this is purely a way for the dashboard to show what's already
//! registered and whether each is currently reachable.

use kiln_image::store::Store;
use kilnd_core::http::Response;
use serde::Serialize;

#[derive(Serialize)]
pub struct NodeJson {
    pub name: String,
    pub address: String,
    pub reachable: bool,
}

pub fn list(store: &Store) -> Response {
    let out: Vec<NodeJson> = kiln_cli::commands::node::load_nodes(store)
        .into_iter()
        .map(|n| {
            let reachable = kiln_cli::commands::node::ping(&n);
            NodeJson {
                name: n.name,
                address: n.address,
                reachable,
            }
        })
        .collect();
    Response::json(200, &out)
}
