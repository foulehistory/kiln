use kiln_cli::container::{Container, Status};
use kiln_image::store::Store;
use kilnd_core::conn::Conn;
use kilnd_core::http::{Request, Response};
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
    /// The `--memory`/`--cpus` this container was started with, if any -
    /// already persisted on `Container` for `kiln start`'s benefit, just
    /// not previously serialized here. Lets a client compare live usage
    /// (`stats()` below) against the limit it's actually running under,
    /// e.g. for a "near its memory limit" alert.
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit: Option<f64>,
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
        memory_limit_bytes: c.memory_limit_bytes,
        cpu_limit: c.cpu_limit,
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

#[derive(Deserialize)]
pub struct UpdateLimitsRequest {
    /// e.g. `"512m"`, `"1g"`, or omitted/null for unlimited - same
    /// `commands::run::parse_size` format `RunRequest::memory` above
    /// already uses, so the dashboard's "New container" and "Edit
    /// limits" forms behave identically.
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default)]
    pub cpus: Option<f64>,
}

/// Changes a container's memory/CPU limits *live*, without a restart -
/// cgroups v2's `memory.max`/`cpu.max` are ordinary files that take
/// effect on write regardless of whether the cgroup currently has member
/// processes (see kilnd-core::cgroups::CgroupV2::apply_limits, the same
/// code `kiln run --memory/--cpus` uses at creation time). Also persists
/// the new values on the container's own state so a later `kiln start`
/// reapplies them instead of reverting to whatever was set at the
/// original `kiln run`.
pub fn update_limits(store: &Store, id: &str, req: &Request) -> Response {
    let Some(mut c) = Container::resolve(store, id) else {
        return Response::text(404, "no such container");
    };
    let body: UpdateLimitsRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let memory_limit_bytes = match body.memory.as_deref().map(kiln_cli::commands::run::parse_size).transpose() {
        Ok(v) => v,
        Err(e) => return Response::text(400, e),
    };

    let Some(cgroup_dir) = kiln_cli::cgroup::open(&c.id) else {
        return Response::text(404, "container has no cgroup (has it ever been started?)");
    };
    let cgroup = kilnd_core::cgroups::CgroupV2::from_existing(cgroup_dir);
    let limits = kilnd_core::cgroups::Limits {
        cpu_max_us: body.cpus.map(|cpus| (cpus * 100_000.0) as u64),
        cpu_period_us: 100_000,
        memory_max_bytes: memory_limit_bytes,
        // See Limits::memory_swap_max_bytes's docs - without also capping
        // swap, a memory limit isn't really a hard cap.
        memory_swap_max_bytes: memory_limit_bytes.map(|_| 0),
        pids_max: None,
    };
    if let Err(e) = cgroup.apply_limits(&limits) {
        return Response::text(500, format!("{e}"));
    }

    c.memory_limit_bytes = memory_limit_bytes;
    c.cpu_limit = body.cpus;
    if let Err(e) = c.save(store) {
        return Response::text(500, format!("limits applied live but failed to persist for next start: {e}"));
    }

    Response::json(200, &to_json(c, store))
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
    /// e.g. `"512m"`, `"1g"` - see `commands::run::parse_size`.
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default)]
    pub cpus: Option<f64>,
    #[serde(default)]
    pub ports: Vec<String>,
    /// `"no"` (default), `"always"`, or `"on-failure"`.
    #[serde(default)]
    pub restart: Option<String>,
    /// Names of secrets (already created via `kiln secret create`) to
    /// mount at `/run/secrets/` - same role as `kiln run --secret`.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Same three fields as `kiln run --security-opt`/`--cap-add`/
    /// `--cap-drop` - see `kilnd_core::security::SecurityProfile`.
    #[serde(default)]
    pub seccomp_unconfined: bool,
    #[serde(default)]
    pub cap_add: Vec<String>,
    #[serde(default)]
    pub cap_drop: Vec<String>,
}

pub fn create(store: &Store, req: &Request) -> Response {
    let body: RunRequest = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::text(400, format!("invalid JSON body: {e}")),
    };
    let memory_limit_bytes = match body.memory.as_deref().map(kiln_cli::commands::run::parse_size).transpose() {
        Ok(v) => v,
        Err(e) => return Response::text(400, e),
    };
    let restart_policy = match body.restart.as_deref().map(kiln_cli::container::RestartPolicy::parse).transpose() {
        Ok(v) => v.unwrap_or_default(),
        Err(e) => return Response::text(400, e),
    };

    let mut spec = kiln_cli::commands::run::RunSpec::new(body.image);
    spec.command = body.command;
    spec.name = body.name;
    spec.volumes = body.volumes;
    spec.network = body.network;
    spec.extra_env = body.environment;
    spec.memory_limit_bytes = memory_limit_bytes;
    spec.cpu_limit = body.cpus;
    spec.restart_policy = restart_policy;
    spec.ports = body.ports;
    spec.secrets = body.secrets;
    spec.security = kilnd_core::security::SecurityProfile {
        seccomp_unconfined: body.seccomp_unconfined,
        cap_add: body.cap_add,
        cap_drop: body.cap_drop,
    };

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
/// "did it actually die" check `remove` already used.
fn cgroup_is_empty(id: &str) -> bool {
    kiln_cli::cgroup::open(id)
        .and_then(|dir| std::fs::read_to_string(dir.join("cgroup.procs")).ok())
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
}

/// Delegates to `kiln stop`'s own implementation (`kiln_cli::commands::stop`)
/// rather than keeping a second copy of the SIGTERM/grace-period/SIGKILL
/// dance here - that exact duplication (this handler had it, the CLI
/// didn't) is how this handler's copy once regressed to a SIGTERM-only
/// version that silently did nothing.
pub fn stop(store: &Store, id: &str) -> Response {
    match kiln_cli::commands::stop::stop_container(store, id) {
        Ok(c) => Response::json(200, &to_json(c, store)),
        Err(e) => Response::text(404, format!("{e}")),
    }
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
        return (Response {
            status: 200,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body,
        })
        .write_to(stream);
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
