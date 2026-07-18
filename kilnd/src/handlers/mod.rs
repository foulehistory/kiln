pub mod containers;
pub mod exec;
pub mod images;
pub mod networks;
pub mod volumes;

use crate::conn::Conn;
use crate::http::{Request, Response};
use kiln_image::store::Store;
use std::io::{self, BufReader};

pub fn route(store: &Store, req: &Request, stream: &mut Conn, reader: &mut BufReader<Conn>) -> io::Result<()> {
    let segments: Vec<&str> = req.path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    match (req.method.as_str(), segments.as_slice()) {
        ("GET", ["version"]) => {
            Response::json(200, &serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })).write_to(stream)
        }
        ("GET", ["containers"]) => containers::list(store).write_to(stream),
        ("POST", ["containers"]) => containers::create(store, req).write_to(stream),
        ("GET", ["containers", id]) => containers::inspect(store, id).write_to(stream),
        ("DELETE", ["containers", id]) => containers::remove(store, id).write_to(stream),
        ("GET", ["containers", id, "stats"]) => containers::stats(store, id).write_to(stream),
        ("POST", ["containers", id, "stop"]) => containers::stop(store, id).write_to(stream),
        ("POST", ["containers", id, "start"]) => containers::start_existing(store, id).write_to(stream),
        ("GET", ["containers", id, "logs"]) => containers::logs(store, id, req, stream),
        ("GET", ["containers", id, "exec"]) if req.is_upgrade_to("kiln-exec") => exec::handle(store, id, req, stream, reader),
        ("GET", ["images"]) => images::list(store).write_to(stream),
        ("POST", ["images", "pull"]) => images::pull(store, req).write_to(stream),
        ("DELETE", ["images", id]) => images::remove(store, id).write_to(stream),
        ("GET", ["networks"]) => networks::list(store).write_to(stream),
        ("POST", ["networks"]) => networks::create(store, req).write_to(stream),
        ("DELETE", ["networks", name]) => networks::remove(store, name).write_to(stream),
        ("GET", ["volumes"]) => volumes::list(store).write_to(stream),
        ("POST", ["volumes"]) => volumes::create(store, req).write_to(stream),
        ("DELETE", ["volumes", name]) => volumes::remove(store, name).write_to(stream),
        _ => Response::text(404, "not found").write_to(stream),
    }
}
