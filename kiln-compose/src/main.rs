//! `kiln-compose`: multi-container orchestration for Kiln, driven by a
//! `kiln.yaml` file. Built entirely on top of `kiln-cli`'s own
//! `RunSpec`/`start` machinery (see `kiln_cli::commands::run`) - a
//! project's services are just ordinary `kiln run` containers, named
//! `<project>_<service>`, attached to one shared `<project>_default`
//! network.
//!
//! # Service discovery: what it does and doesn't do
//!
//! Services reach each other by name via `/etc/hosts` entries injected
//! before each container starts (`RunSpec::extra_hosts`), not a real DNS
//! server. Because services start in dependency order, a service only
//! ever gets host entries for services that were *already running* when
//! it started - i.e. its own transitive `depends_on` - not for services
//! that happen to start after it. This covers the common case (a web
//! service resolving `db` because it correctly declares `depends_on:
//! [db]`) without the complexity of an embedded DNS resolver.

mod compose;

use clap::{Parser, Subcommand};
use compose::{ComposeFile, Service};
use kiln_cli::commands::network::{self, NetworkConfig};
use kiln_cli::commands::run::{start, RunSpec};
use kiln_cli::commands::volume;
use kiln_cli::container::{Container, Status};
use kiln_cli::error::{CliError, CliResult};
use kiln_image::image::normalize_repository;
use kiln_image::store::Store;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "kiln-compose", version, about = "Multi-container orchestration for Kiln")]
struct Cli {
    /// Path to the compose file
    #[arg(short = 'f', long, default_value = "kiln.yaml")]
    file: PathBuf,

    /// Project name (defaults to the compose file's directory name)
    #[arg(short = 'p', long)]
    project_name: Option<String>,

    /// Path to the Kiln store (defaults to $KILN_STORE, or ~/.kiln)
    #[arg(long)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start every service, in dependency order
    Up(UpArgs),
    /// Stop and remove every service's container
    Down,
    /// Show each service's container status
    Ps,
    /// Fetch (optionally follow) aggregated, per-service-prefixed logs
    Logs(LogsArgs),
    /// Build every service with a `build:` context
    Build,
}

#[derive(clap::Args)]
struct UpArgs {
    /// Start in the background instead of streaming aggregated logs
    #[arg(short = 'd', long)]
    detach: bool,
}

#[derive(clap::Args)]
struct LogsArgs {
    #[arg(short = 'f', long)]
    follow: bool,
}

fn main() {
    let cli = Cli::parse();
    let store_root = cli.store.unwrap_or_else(kiln_cli::default_store);
    let store = match Store::open(&store_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln-compose: opening store at {}: {e}", store_root.display());
            std::process::exit(1);
        }
    };

    let source = match std::fs::read_to_string(&cli.file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln-compose: reading {}: {e}", cli.file.display());
            std::process::exit(1);
        }
    };
    let compose: ComposeFile = match compose::parse(&source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kiln-compose: parsing {}: {e}", cli.file.display());
            std::process::exit(1);
        }
    };

    let context_dir = cli.file.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let project = project_name(cli.project_name, &cli.file);

    let result = match cli.command {
        Command::Up(args) => cmd_up(&store, &project, &context_dir, &compose, args.detach),
        Command::Down => cmd_down(&store, &project, &compose),
        Command::Ps => cmd_ps(&store, &project, &compose),
        Command::Logs(args) => cmd_logs(&store, &project, &compose, args.follow),
        Command::Build => cmd_build(&store, &project, &context_dir, &compose),
    };

    if let Err(e) = result {
        eprintln!("kiln-compose: {e}");
        std::process::exit(1);
    }
}

fn project_name(explicit: Option<String>, file: &Path) -> String {
    let raw = explicit.unwrap_or_else(|| {
        let dir = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .and_then(|p| p.canonicalize().ok())
            .or_else(|| std::env::current_dir().ok());
        dir.and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "kiln".to_string())
    });
    raw.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

fn pick_subnet(project: &str) -> String {
    let mut hasher = DefaultHasher::new();
    project.hash(&mut hasher);
    let octet = 20 + (hasher.finish() % 200);
    format!("172.{octet}.0.0/24")
}

fn resolve_service_image(store: &Store, project: &str, context_dir: &Path, name: &str, svc: &Service) -> CliResult<String> {
    if let Some(build_path) = &svc.build {
        let build_ctx = context_dir.join(build_path);
        let kilnfile_path = build_ctx.join("Kilnfile");
        let source = std::fs::read_to_string(&kilnfile_path)
            .map_err(|e| CliError::msg(format!("service {name}: reading {}: {e}", kilnfile_path.display())))?;
        let output =
            kiln_image::build::build(store, &build_ctx, &source).map_err(|e| CliError::msg(format!("service {name}: build failed: {e}")))?;
        let repo = normalize_repository(&format!("{project}_{name}"));
        store.tag(&repo, "latest", output.image_id)?;
        Ok(format!("{repo}:latest"))
    } else if let Some(image) = &svc.image {
        Ok(image.clone())
    } else {
        Err(CliError::msg(format!("service {name:?} has neither `image` nor `build`")))
    }
}

fn cmd_build(store: &Store, project: &str, context_dir: &Path, compose: &ComposeFile) -> CliResult {
    for (name, svc) in &compose.services {
        if svc.build.is_none() {
            continue;
        }
        println!("Building {name}...");
        let image = resolve_service_image(store, project, context_dir, name, svc)?;
        println!("{name} built: {image}");
    }
    Ok(())
}

fn cmd_up(store: &Store, project: &str, context_dir: &Path, compose: &ComposeFile, detach: bool) -> CliResult {
    for vol_name in compose.volumes.keys() {
        std::fs::create_dir_all(volume::path(store, vol_name))?;
    }

    let network_name = format!("{project}_default");
    if NetworkConfig::load(store, &network_name).is_none() {
        network::run(store, network::Command::Create { name: network_name.clone(), subnet: pick_subnet(project) })?;
    }

    let order = compose::dependency_order(&compose.services).map_err(CliError::msg)?;

    let mut started = Vec::new();
    let mut hosts: Vec<(String, String)> = Vec::new();

    for name in &order {
        let svc = &compose.services[name];
        let container_name = format!("{project}_{name}");

        if let Some(mut existing) = Container::resolve(store, &container_name) {
            existing.refresh(store);
            if existing.status == Status::Running {
                println!("{name} already running ({})", &existing.id[..12]);
                if let Some(ip) = &existing.ip {
                    hosts.push((name.clone(), ip.clone()));
                }
                started.push(existing);
                continue;
            }
        }

        let image = resolve_service_image(store, project, context_dir, name, svc)?;

        let mut spec = RunSpec::new(image);
        spec.command = svc.command.clone().map(|c| c.into_vec()).unwrap_or_default();
        spec.name = Some(container_name);
        spec.volumes = svc.volumes.clone();
        spec.ports = svc.ports.clone();
        spec.network = Some(network_name.clone());
        spec.extra_env = svc.environment.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        spec.extra_hosts = hosts.clone();

        println!("Starting {name}...");
        let container = start(store, spec, None).map_err(|e| CliError::msg(format!("service {name}: {e}")))?;
        if let Some(ip) = &container.ip {
            println!("  {name}: {} ({ip})", &container.id[..12]);
            hosts.push((name.clone(), ip.clone()));
        }
        started.push(container);
    }

    if detach {
        Ok(())
    } else {
        stream_aggregated_logs(store, &started, true)
    }
}

fn cmd_down(store: &Store, project: &str, compose: &ComposeFile) -> CliResult {
    for name in compose.services.keys() {
        let container_name = format!("{project}_{name}");
        let Some(mut c) = Container::resolve(store, &container_name) else { continue };
        c.refresh(store);
        if c.status == Status::Running {
            if let Some(pid) = c.pid {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
        }
        let dir = Container::dir(store, &c.id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => println!("removed {container_name}"),
            Err(e) => eprintln!("kiln-compose: removing {container_name}: {e}"),
        }
    }

    // `up` always creates (or reuses) a `<project>_default` bridge network
    // for the project's services - `down` used to leave it (and its
    // iptables MASQUERADE rule) behind entirely, the same class of orphan
    // as the bridges that needed manual `ip link del` cleanup during
    // development. Tear it down the same way `kiln network rm` would;
    // tolerate it already being gone (e.g. a project that was never
    // actually brought up, or a `down` run twice).
    let network_name = format!("{project}_default");
    if NetworkConfig::load(store, &network_name).is_some() {
        match network::run(store, network::Command::Rm { name: network_name.clone() }) {
            Ok(()) => println!("removed network {network_name}"),
            Err(e) => eprintln!("kiln-compose: removing network {network_name}: {e}"),
        }
    }

    Ok(())
}

fn cmd_ps(store: &Store, project: &str, compose: &ComposeFile) -> CliResult {
    println!("{:<20}{:<14}{:<14}{:<8}COMMAND", "SERVICE", "CONTAINER ID", "STATUS", "PID");
    for name in compose.services.keys() {
        let container_name = format!("{project}_{name}");
        match Container::resolve(store, &container_name) {
            Some(mut c) => {
                c.refresh(store);
                let status = match c.status {
                    Status::Running => "running".to_string(),
                    Status::Exited(code) => format!("exited({code})"),
                };
                let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
                println!("{:<20}{:<14}{:<14}{:<8}{}", name, &c.id[..12.min(c.id.len())], status, pid, c.command.join(" "));
            }
            None => println!("{:<20}{:<14}{:<14}{:<8}", name, "-", "not created", ""),
        }
    }
    Ok(())
}

fn cmd_logs(store: &Store, project: &str, compose: &ComposeFile, follow: bool) -> CliResult {
    let containers: Vec<Container> =
        compose.services.keys().filter_map(|name| Container::resolve(store, &format!("{project}_{name}"))).collect();

    if containers.is_empty() {
        println!("no containers for this project - run `kiln-compose up` first");
        return Ok(());
    }

    if follow {
        stream_aggregated_logs(store, &containers, false)
    } else {
        for c in &containers {
            let log_path = Container::log_path(store, &c.id);
            if let Ok(content) = std::fs::read_to_string(&log_path) {
                for line in content.lines() {
                    println!("{} | {line}", c.name);
                }
            }
        }
        Ok(())
    }
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

/// Tail every container's log concurrently, each line prefixed with its
/// service name, until Ctrl-C. If `own_containers` (true only for `up`'s
/// own foreground mode, never for `logs -f`), Ctrl-C also stops every
/// container - mirroring `docker-compose up`'s "foreground is the
/// lifetime" behavior; `kiln-compose logs -f` just detaches from watching
/// without touching anything.
fn stream_aggregated_logs(store: &Store, containers: &[Container], own_containers: bool) -> CliResult {
    STOP.store(false, Ordering::SeqCst);
    unsafe {
        let _ = nix::sys::signal::signal(nix::sys::signal::Signal::SIGINT, nix::sys::signal::SigHandler::Handler(handle_sigint));
    }

    let store_root = store.root().to_path_buf();
    let mut handles = Vec::new();
    for c in containers {
        let store_root = store_root.clone();
        let id = c.id.clone();
        let name = c.name.clone();
        handles.push(std::thread::spawn(move || {
            let Ok(store) = Store::open(&store_root) else { return };
            let log_path = Container::log_path(&store, &id);
            let mut pos = 0u64;
            while !STOP.load(Ordering::SeqCst) {
                if let Ok(mut file) = std::fs::File::open(&log_path) {
                    use std::io::{Read, Seek, SeekFrom};
                    if let Ok(meta) = file.metadata() {
                        if meta.len() > pos {
                            file.seek(SeekFrom::Start(pos)).ok();
                            let mut chunk = String::new();
                            file.read_to_string(&mut chunk).ok();
                            for line in chunk.lines() {
                                println!("{name} | {line}");
                            }
                            pos += chunk.len() as u64;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }));
    }

    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }

    if own_containers {
        println!("\nStopping...");
        for c in containers {
            if let Some(pid) = c.pid {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGTERM);
            }
        }
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

