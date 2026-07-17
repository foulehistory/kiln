use crate::conn::Conn;
use crate::http::{Request, Response};
use kiln_cli::container::{Container, Status};
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::time::Duration;

#[derive(Serialize)]
pub struct ContainerJson {
    pub id: String,
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub status: String,
    pub pid: Option<i32>,
    pub ip: Option<String>,
    pub network: Option<String>,
    pub created_at: u64,
}

fn to_json(mut c: Container, store: &Store) -> ContainerJson {
    c.refresh(store);
    let status = match c.status {
        Status::Running => "running".to_string(),
        Status::Exited(code) => format!("exited({code})"),
    };
    ContainerJson {
        id: c.id,
        name: c.name,
        image: c.image_reference,
        command: c.command,
        status,
        pid: c.pid,
        ip: c.ip,
        network: c.network,
        created_at: c.created_at,
    }
}

pub fn list(store: &Store) -> Response {
    let containers: Vec<ContainerJson> = Container::list(store).into_iter().map(|c| to_json(c, store)).collect();
    Response::json(200, &containers)
}

pub fn inspect(store: &Store, id: &str) -> Response {
    match Container::resolve(store, id) {
        Some(c) => Response::json(200, &to_json(c, store)),
        None => Response::text(404, "no such container"),
    }
}

pub fn stats(store: &Store, id: &str) -> Response {
    let Some(c) = Container::resolve(store, id) else {
        return Response::text(404, "no such container");
    };
    match kiln_cli::cgroup::stats(&c.id) {
        Some(s) => Response::json(200, &s),
        None => Response::text(404, "no stats available (container may not be running)"),
    }
}

#[derive(Deserialize)]
pub struct RunRequest {
    pub image: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub environment: Vec<(String, String)>,
}

pub fn create(store: &Store, req: &Request) -> Response {
    let body: RunRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };

    let mut spec = kiln_cli::commands::run::RunSpec::new(body.image);
    spec.command = body.command;
    spec.name = body.name;
    spec.volumes = body.volumes;
    spec.network = body.network;
    spec.extra_env = body.environment;

    match kiln_cli::commands::run::start(store, spec, None) {
        Ok(c) => Response::json(201, &to_json(c, store)),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

pub fn start_existing(store: &Store, id: &str) -> Response {
    match kiln_cli::commands::run::restart(store, id) {
        Ok(c) => Response::json(200, &to_json(c, store)),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

/// True once `id`'s cgroup has no resident processes left - the same
/// "did it actually die" check `remove` already used, reused here so
/// `stop` can tell whether `SIGTERM` actually worked before deciding
/// whether it needs to escalate.
fn cgroup_is_empty(id: &str) -> bool {
    kiln_cli::cgroup::open(id)
        .and_then(|dir| std::fs::read_to_string(dir.join("cgroup.procs")).ok())
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
}

pub fn stop(store: &Store, id: &str) -> Response {
    let Some(c) = Container::resolve(store, id) else {
        return Response::text(404, "no such container");
    };
    let Some(pid) = c.pid else {
        return Response::text(204, "");
    };
    let pid = nix::unistd::Pid::from_raw(pid);

    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);

    // SIGTERM is not reliably enough on its own: a container's command
    // runs as PID 1 of its own PID namespace (kiln has no separate init
    // layer - see run.rs's module docs), and per pid_namespaces(7), a
    // namespace's PID 1 silently discards any signal whose default
    // action is "terminate" unless it explicitly installed a handler for
    // that exact signal. Most commands never do that for SIGTERM, so
    // without a fallback `stop` would report success (the kill(2) syscall
    // itself does succeed) while the container just keeps running - which
    // is exactly what was happening before this grace-period/SIGKILL
    // fallback existed. `docker stop` has the identical two-step shape
    // for the identical reason.
    let mut exited = false;
    for _ in 0..50 {
        if cgroup_is_empty(&c.id) {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !exited {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    }

    Response::text(204, "")
}

pub fn remove(store: &Store, id: &str) -> Response {
    let Some(mut c) = Container::resolve(store, id) else {
        return Response::text(404, "no such container");
    };
    c.refresh(store);
    if c.status == Status::Running {
        if let Some(pid) = c.pid {
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
        }
        for _ in 0..10 {
            if cgroup_is_empty(&c.id) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    kiln_cli::cgroup::remove(&c.id);

    let dir = Container::dir(store, &c.id);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Response::text(204, ""),
        Err(e) => Response::text(500, format!("{e}")),
    }
}

/// Unlike every other handler here, this one writes directly to `stream`
/// instead of returning a `Response`: `?follow=1` never has a fixed
/// `Content-Length`, so it streams via `Transfer-Encoding: chunked`,
/// polling the log file for new bytes until the container exits.
pub fn logs(store: &Store, id: &str, req: &Request, stream: &mut Conn) -> io::Result<()> {
    let Some(c) = Container::resolve(store, id) else {
        return Response::text(404, "no such container").write_to(stream);
    };
    let follow = matches!(req.query.get("follow").map(String::as_str), Some("1") | Some("true"));
    let log_path = Container::log_path(store, &c.id);

    if !follow {
        let body = std::fs::read(&log_path).unwrap_or_default();
        return (Response { status: 200, headers: vec![("Content-Type".into(), "text/plain".into())], body }).write_to(stream);
    }

    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n"
    )?;

    let mut file = match std::fs::File::open(&log_path) {
        Ok(f) => f,
        Err(_) => return write_final_chunk(stream),
    };
    let mut pos = 0u64;
    loop {
        let len = file.metadata()?.len();
        if len > pos {
            file.seek(SeekFrom::Start(pos))?;
            let mut chunk = Vec::new();
            file.read_to_end(&mut chunk)?;
            write!(stream, "{:x}\r\n", chunk.len())?;
            stream.write_all(&chunk)?;
            write!(stream, "\r\n")?;
            stream.flush()?;
            pos += chunk.len() as u64;
        }

        let mut current = Container::resolve(store, &c.id).unwrap_or_else(|| c.clone());
        current.refresh(store);
        if current.status != Status::Running {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    write_final_chunk(stream)
}

fn write_final_chunk(stream: &mut Conn) -> io::Result<()> {
    write!(stream, "0\r\n\r\n")?;
    stream.flush()
}
