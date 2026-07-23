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
//!
//! Cross-host (`node:`-tagged) services get the same treatment, with one
//! real difference: since there's no overlay network between nodes'
//! completely separate container subnets, a `node:`-tagged dependency
//! resolves to *its node's own host address* (see `node_host`), not a
//! container-internal IP - the dependent service must reach it via a
//! `ports:`-published port it already knows to use, since there's no
//! dynamic port lookup here. A service depending on a plain *local*
//! (non-`node:`) one from a *different* node has no such address to
//! resolve to (there's no reliable "this machine's own externally-
//! reachable address" to hand out) and gets nothing, same as always.

mod backup;
mod compose;
mod dotenv;
mod remote;

use clap::{Parser, Subcommand};
use compose::{ComposeFile, Healthcheck, Service};
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
    /// Archive kiln.yaml + every declared volume's contents into one file
    /// (secret values are never included - see `backup`'s module docs)
    Backup(BackupArgs),
    /// Recreate kiln.yaml and every volume from a `backup` archive
    Restore(RestoreArgs),
    /// Create a `node:`-tagged service fresh on a different registered
    /// node - never automatic (see this crate's own module docs on why
    /// there's no automatic failover): run this yourself once you've
    /// noticed a node is down, e.g. via `kiln node ls`'s own reachability
    /// check.
    Reschedule(RescheduleArgs),
}

#[derive(clap::Args)]
struct RescheduleArgs {
    /// The service name, as it appears in kiln.yaml
    service: String,
    /// Name of an already-registered node (`kiln node ls`) to create it
    /// on instead
    to: String,
}

#[derive(clap::Args)]
struct BackupArgs {
    /// Output path (defaults to `<project>-<unix-timestamp>.kiln-backup.tar`
    /// in the current directory)
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct RestoreArgs {
    /// A `.kiln-backup.tar` archive produced by `kiln-compose backup`
    archive: PathBuf,
    /// Directory to restore kiln.yaml into (defaults to the current
    /// directory)
    #[arg(long)]
    dest: Option<PathBuf>,
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

    // `restore` deliberately doesn't need a `kiln.yaml` to already exist -
    // recreating it from the archive is the whole point - so it's handled
    // before the read below, which every other subcommand needs.
    if let Command::Restore(args) = &cli.command {
        if let Err(e) = backup::restore(&store, &args.archive, args.dest.clone()) {
            eprintln!("kiln-compose: {e}");
            std::process::exit(1);
        }
        return;
    }

    let context_dir = cli.file.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));

    let source = match std::fs::read_to_string(&cli.file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln-compose: reading {}: {e}", cli.file.display());
            std::process::exit(1);
        }
    };
    // `.env` (if present, next to kiln.yaml - docker-compose's own
    // convention) provides values for `${VAR}` interpolation in the raw
    // text below, before it's ever handed to `compose::parse` - see
    // `dotenv.rs`'s own docs on exactly what this does and doesn't do.
    let dotenv = dotenv::load(&context_dir);
    let source = match dotenv::interpolate(&source, &dotenv) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln-compose: interpolating {}: {e}", cli.file.display());
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
    let project = project_name(cli.project_name, &cli.file);

    let result = match cli.command {
        Command::Up(args) => cmd_up(&store, &project, &context_dir, &compose, args.detach),
        Command::Down => cmd_down(&store, &project, &compose),
        Command::Ps => cmd_ps(&store, &project, &compose),
        Command::Logs(args) => cmd_logs(&store, &project, &compose, args.follow),
        Command::Build => cmd_build(&store, &project, &context_dir, &compose),
        Command::Backup(args) => backup::backup(&store, &project, &cli.file, &compose, args.output),
        Command::Restore(_) => unreachable!("handled above"),
        Command::Reschedule(args) => cmd_reschedule(&store, &project, &context_dir, &compose, &args.service, &args.to),
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
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect()
}

fn pick_subnet(project: &str) -> String {
    let mut hasher = DefaultHasher::new();
    project.hash(&mut hasher);
    let octet = 20 + (hasher.finish() % 200);
    format!("172.{octet}.0.0/24")
}

/// Cross-host service discovery is deliberately narrow: there is no
/// overlay/VPN between nodes (containers on different nodes sit on
/// completely separate, unrouted bridge subnets), so the only address
/// that means anything to *another machine* is the node's own host
/// address - the same one already used to reach its `kilnd`. This
/// resolves a name to that host address only; it is the caller's own
/// responsibility to `ports:`-publish the target service on a port the
/// consumer already expects to use (there's no dynamic port lookup here,
/// just a name -> host-IP mapping via `/etc/hosts`, same mechanism the
/// same-host case already used before this).
fn node_host(node: &kiln_cli::commands::node::Node) -> String {
    node.address.split(':').next().unwrap_or(&node.address).to_string()
}

fn resolve_service_image(store: &Store, project: &str, context_dir: &Path, name: &str, svc: &Service) -> CliResult<String> {
    if svc.build.is_some() && svc.node.is_some() {
        // Shipping the build context itself to a node that might not
        // even share this machine's filesystem layout is real complexity
        // this MVP doesn't take on. But `build:` + `node:` + `image:`
        // together *is* supported (see the branch below): build locally,
        // push the result to the registry `image:` names, then have the
        // remote node pull that same reference - the same "build here,
        // push, deploy there" shape `docker compose`'s own `build:` +
        // `image:` combination has, and it reuses the registry push/pull
        // path this project already has rather than inventing a second
        // one.
        if svc.image.is_none() {
            return Err(CliError::msg(format!(
                "service {name:?}: `build:` + `node:` needs `image:` too - a registry reference the remote node can pull the built image back from (same as `docker compose`'s own build:+image: combination)"
            )));
        }
    }
    if let Some(build_path) = &svc.build {
        let build_ctx = context_dir.join(build_path);
        let kilnfile_path = build_ctx.join("Kilnfile");
        let source = std::fs::read_to_string(&kilnfile_path)
            .map_err(|e| CliError::msg(format!("service {name}: reading {}: {e}", kilnfile_path.display())))?;
        let output = kiln_image::build::build(store, &build_ctx, &source).map_err(|e| CliError::msg(format!("service {name}: build failed: {e}")))?;

        if let (Some(node_name), Some(image_ref)) = (&svc.node, &svc.image) {
            // Tag under the exact reference `image:` names (not the usual
            // `{project}_{name}` local tag - that name has no meaning to
            // whatever registry `image_ref` points at), push it there,
            // then hand the same reference back so the remote dispatch
            // in `cmd_up` pulls precisely what was just pushed.
            let (repo, tag) = kiln_image::image::split_name_tag(image_ref);
            let repo = normalize_repository(repo);
            store.tag(&repo, tag, output.image_id)?;
            println!("  {name}: pushing {image_ref} for node {node_name}...");
            kiln_image::registry::push(store, &output.image_id, image_ref)
                .map_err(|e| CliError::msg(format!("service {name}: pushing {image_ref}: {e}")))?;
            return Ok(image_ref.clone());
        }

        let repo = normalize_repository(&format!("{project}_{name}"));
        store.tag(&repo, "latest", output.image_id)?;
        Ok(format!("{repo}:latest"))
    } else if let Some(image) = &svc.image {
        Ok(image.clone())
    } else {
        Err(CliError::msg(format!("service {name:?} has neither `image` nor `build`")))
    }
}

/// Builds/resolves `svc`'s image and creates it on `node` - the shared
/// core of `cmd_up`'s own node-tagged dispatch and `cmd_reschedule`
/// (which calls this with an explicit *different* node than `svc.node`
/// names, precisely because it exists to move a service somewhere else
/// without waiting for `svc.node` itself to change).
#[allow(clippy::too_many_arguments)] // two call sites, both already assembling exactly these values; a params struct would just move them, not reduce them
fn dispatch_remote_service(
    store: &Store,
    project: &str,
    context_dir: &Path,
    name: &str,
    svc: &Service,
    node: &kiln_cli::commands::node::Node,
    node_name: &str,
    network_name: &str,
    hosts: &[(String, String)],
) -> CliResult<remote::RemoteContainer> {
    let mut image = resolve_service_image(store, project, context_dir, name, svc)?;
    if !svc.ports.is_empty() {
        remote::ensure_remote_network(node, network_name, &pick_subnet(project));
    }
    if svc.build.is_some() {
        // `resolve_service_image` just pushed this image to the registry
        // `image:` names - the remote node never has it yet (kilnd never
        // auto-pulls a missing local tag, see `remote::pull_image`'s own
        // docs), so it needs telling explicitly before `create_container`
        // below can resolve it.
        println!("  {name}: pulling {image} on {node_name}...");
        remote::pull_image(node, &image)?;
        // A pull tags the result locally under the *host-stripped*
        // repository (see `kiln_image::registry::Reference::parse`'s own
        // docs: the host is routing information for where to fetch from,
        // not part of the local tag's identity) - the remote node's own
        // `Image::resolve` for the create call right below needs that
        // same host-stripped form, not the full `image:` reference
        // `pull_image` was just given.
        let reference = kiln_image::registry::Reference::parse(&image);
        image = format!("{}:{}", reference.repository, reference.tag);
    }

    let container_name = format!("{project}_{name}");
    println!("Starting {name} on {node_name}...");
    let args = remote::RunArgs {
        name: container_name,
        image,
        command: svc.command.clone().map(|c| c.into_vec()).unwrap_or_default(),
        volumes: svc.volumes.clone(),
        network: if svc.ports.is_empty() { None } else { Some(network_name.to_string()) },
        environment: svc.environment.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ports: svc.ports.clone(),
        secrets: svc.secrets.clone(),
        extra_hosts: hosts.to_vec(),
        memory: svc.resources.as_ref().and_then(|r| r.memory.clone()),
        memory_swap: svc.resources.as_ref().and_then(|r| r.memory_swap.clone()),
        cpus: svc
            .resources
            .as_ref()
            .and_then(|r| r.cpu.as_deref())
            .map(|s| s.parse::<f64>())
            .transpose()
            .map_err(|_| CliError::msg(format!("service {name:?}: invalid resources.cpu")))?,
        security: kilnd_core::security::SecurityProfile {
            seccomp_unconfined: svc.security_opt.iter().any(|s| s == "seccomp:unconfined"),
            cap_add: svc.cap_add.clone(),
            cap_drop: svc.cap_drop.clone(),
        },
        healthcheck: svc.healthcheck.clone().map(Healthcheck::into_spec).transpose().map_err(CliError::msg)?,
    };
    let container = remote::create_container(node, args)?;
    println!("  {name}: {} on {node_name}", &container.id[..12.min(container.id.len())]);
    Ok(container)
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

/// Creates `service` fresh on `to_node_name`, bypassing whatever `node:`
/// it's actually declared under in `kiln.yaml` - the explicit,
/// never-automatic response to a node going unreachable (`kiln node ls`
/// already surfaces that; nothing here watches for it or reacts on its
/// own). Deliberately does not touch `kiln.yaml` itself: silently
/// rewriting the user's own file out from under them on their behalf
/// would be a much bigger surprise than printing a one-line reminder to
/// do it themselves for the change to survive the next `up`.
fn cmd_reschedule(store: &Store, project: &str, context_dir: &Path, compose: &ComposeFile, service: &str, to_node_name: &str) -> CliResult {
    let svc = compose
        .services
        .get(service)
        .ok_or_else(|| CliError::msg(format!("no such service: {service:?}")))?;
    let Some(from_node_name) = &svc.node else {
        return Err(CliError::msg(format!(
            "service {service:?} has no `node:` in kiln.yaml - it isn't a remote service, there's nothing to reschedule"
        )));
    };
    let to_node = kiln_cli::commands::node::find_node(store, to_node_name)
        .ok_or_else(|| CliError::msg(format!("no such node: {to_node_name:?} (see `kiln node ls`)")))?;

    if let Some(from_node) = kiln_cli::commands::node::find_node(store, from_node_name) {
        if kiln_cli::commands::node::ping(&from_node) {
            println!(
                "note: {from_node_name} (where {service} currently runs) is still reachable - its container there is NOT being stopped automatically; you may want to remove it yourself once {to_node_name} is confirmed healthy."
            );
        }
    }

    let network_name = format!("{project}_default");
    // Best-effort discovery entries for the rescheduled service's own
    // dependencies - only covers other `node:`-tagged services (see
    // `node_host`'s own docs on why a plain local one can't be resolved
    // the same way), and isn't dependency-order-aware the way `cmd_up`'s
    // own `hosts` list is: this is a single-service action, not a full
    // redeploy.
    let hosts: Vec<(String, String)> = compose
        .services
        .iter()
        .filter(|(name, _)| name.as_str() != service)
        .filter_map(|(name, s)| {
            let node = kiln_cli::commands::node::find_node(store, s.node.as_ref()?)?;
            Some((name.clone(), node_host(&node)))
        })
        .collect();

    dispatch_remote_service(store, project, context_dir, service, svc, &to_node, to_node_name, &network_name, &hosts)?;

    println!("Update kiln.yaml: change `node: {from_node_name}` to `node: {to_node_name}` for service {service:?} so this survives the next `kiln-compose up`.");
    Ok(())
}

fn cmd_up(store: &Store, project: &str, context_dir: &Path, compose: &ComposeFile, detach: bool) -> CliResult {
    for vol_name in compose.volumes.keys() {
        std::fs::create_dir_all(volume::path(store, vol_name))?;
    }

    let network_name = format!("{project}_default");
    if NetworkConfig::load(store.root(), &network_name).is_none() {
        network::run(
            store,
            network::Command::Create {
                name: network_name.clone(),
                subnet: pick_subnet(project),
            },
        )?;
    }

    let order = compose::dependency_order(&compose.services).map_err(CliError::msg)?;

    let mut started = Vec::new();
    let mut remote_started: Vec<RemoteTail> = Vec::new();
    let mut hosts: Vec<(String, String)> = Vec::new();

    for name in &order {
        let svc = &compose.services[name];
        let container_name = format!("{project}_{name}");

        if let Some(node_name) = &svc.node {
            let node = kiln_cli::commands::node::find_node(store, node_name)
                .ok_or_else(|| CliError::msg(format!("service {name}: no such node: {node_name} (see `kiln node ls`)")))?;

            if let Some(existing) = remote::get_container(&node, &container_name) {
                if existing.status == "running" {
                    println!("{name} already running on {node_name} ({})", &existing.id[..12.min(existing.id.len())]);
                    hosts.push((name.clone(), node_host(&node)));
                    remote_started.push(RemoteTail {
                        display_name: name.clone(),
                        node: node.clone(),
                        container_name: container_name.clone(),
                    });
                    continue;
                }
            }

            dispatch_remote_service(store, project, context_dir, name, svc, &node, node_name, &network_name, &hosts)?;
            hosts.push((name.clone(), node_host(&node)));
            remote_started.push(RemoteTail {
                display_name: name.clone(),
                node,
                container_name,
            });
            // A later service (local or on another node) that
            // `depends_on` this one resolves its name to *this node's own
            // host address* (see `node_host`'s own docs on why that's the
            // only address that means anything cross-host, and its
            // "ports:-publish it yourself" limitation). The reverse
            // direction - this service depending on a plain local
            // (non-`node:`) one - isn't resolvable the same way: there's
            // no reliable "this machine's own externally-reachable
            // address" to hand out, so that case still gets nothing,
            // same as before this.
            continue;
        }

        // Reap any dead containers already using this name before looking
        // one up - e.g. after a host/VM restart that killed a container's
        // process but left its directory (and name) behind.
        // Container::resolve refuses to pick among same-named entries once
        // there's more than one, so without this cleanup a restart just
        // left `up` creating a fresh, equally ambiguous container under
        // the same name every time it ran, rather than ever reusing or
        // replacing the dead one.
        for mut candidate in Container::list(store).into_iter().filter(|c| c.name == container_name) {
            candidate.refresh(store);
            if candidate.status != Status::Running {
                let _ = std::fs::remove_dir_all(Container::dir(store, &candidate.id));
            }
        }

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
        spec.secrets = svc.secrets.clone();
        spec.network = Some(network_name.clone());
        spec.extra_env = svc.environment.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        spec.extra_hosts = hosts.clone();
        spec.security = kilnd_core::security::SecurityProfile {
            seccomp_unconfined: svc.security_opt.iter().any(|s| s == "seccomp:unconfined"),
            cap_add: svc.cap_add.clone(),
            cap_drop: svc.cap_drop.clone(),
        };
        spec.restart_policy = svc
            .restart
            .as_deref()
            .map(kiln_cli::container::RestartPolicy::parse)
            .transpose()
            .map_err(CliError::msg)?
            .unwrap_or_default();
        spec.healthcheck = svc.healthcheck.clone().map(Healthcheck::into_spec).transpose().map_err(CliError::msg)?;
        if let Some(resources) = &svc.resources {
            let parsed = resources.parse().map_err(|e| CliError::msg(format!("service {name:?}: {e}")))?;
            spec.cpu_limit = parsed.cpu_limit;
            spec.memory_limit_bytes = parsed.memory_limit_bytes;
            spec.memory_swap_bytes = parsed.memory_swap_bytes;
        }

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
        stream_aggregated_logs(store, &started, &remote_started, true)
    }
}

fn cmd_down(store: &Store, project: &str, compose: &ComposeFile) -> CliResult {
    let mut remote_nodes_used = std::collections::HashSet::new();

    for (name, svc) in &compose.services {
        let container_name = format!("{project}_{name}");

        if let Some(node_name) = &svc.node {
            let Some(node) = kiln_cli::commands::node::find_node(store, node_name) else {
                eprintln!("kiln-compose: removing {container_name}: no such node: {node_name}");
                continue;
            };
            match remote::remove_container(&node, &container_name) {
                Ok(()) => println!("removed {container_name} on {node_name}"),
                Err(e) => eprintln!("kiln-compose: removing {container_name} on {node_name}: {e}"),
            }
            remote_nodes_used.insert(node_name.clone());
            continue;
        }

        // Not Container::resolve: it refuses to pick among same-named
        // entries once there's more than one (e.g. a leftover dead
        // container from before a host/VM restart, alongside a live one
        // started since) - `down` should remove every container under
        // this name regardless, not silently skip it over an ambiguity
        // that resolve() can't settle but down doesn't need settled.
        for mut c in Container::list(store).into_iter().filter(|c| c.name == container_name) {
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
    }

    // `up` always creates (or reuses) a `<project>_default` bridge network
    // for the project's services - `down` used to leave it (and its
    // iptables MASQUERADE rule) behind entirely, the same class of orphan
    // as the bridges that needed manual `ip link del` cleanup during
    // development. Tear it down the same way `kiln network rm` would;
    // tolerate it already being gone (e.g. a project that was never
    // actually brought up, or a `down` run twice).
    let network_name = format!("{project}_default");
    if NetworkConfig::load(store.root(), &network_name).is_some() {
        match network::run(store, network::Command::Rm { name: network_name.clone() }) {
            Ok(()) => println!("removed network {network_name}"),
            Err(e) => eprintln!("kiln-compose: removing network {network_name}: {e}"),
        }
    }

    // Same teardown, per remote node that actually had a service on it -
    // best-effort like the local removal above (a node that's gone
    // unreachable since `up` shouldn't stop `down` from cleaning up
    // everything else).
    for node_name in &remote_nodes_used {
        if let Some(node) = kiln_cli::commands::node::find_node(store, node_name) {
            let _ = remote::remove_network(&node, &network_name);
        }
    }

    Ok(())
}

fn cmd_ps(store: &Store, project: &str, compose: &ComposeFile) -> CliResult {
    println!(
        "{:<20}{:<14}{:<14}{:<11}{:<8}{:<10}{:<12}COMMAND",
        "SERVICE", "CONTAINER ID", "STATUS", "HEALTH", "PID", "CPU(ms)", "MEM"
    );
    for (name, svc) in &compose.services {
        let container_name = format!("{project}_{name}");

        if let Some(node_name) = &svc.node {
            let node = kiln_cli::commands::node::find_node(store, node_name);
            let found = node.as_ref().and_then(|node| remote::get_container(node, &container_name));
            match found {
                Some(c) => {
                    let stats = node.as_ref().and_then(|node| remote::get_stats(node, &container_name));
                    let cpu = stats
                        .as_ref()
                        .map(|s| (s.cpu_usage_usec / 1000).to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let mem = stats
                        .as_ref()
                        .map(|s| s.memory_current_bytes.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<20}{:<14}{:<14}{:<11}{:<8}{:<10}{:<12}(on {node_name})",
                        name,
                        &c.id[..12.min(c.id.len())],
                        c.status,
                        c.health,
                        "",
                        cpu,
                        mem,
                    )
                }
                None => println!(
                    "{:<20}{:<14}{:<14}{:<11}{:<8}{:<10}{:<12}",
                    name,
                    "-",
                    format!("not created (on {node_name})"),
                    "",
                    "",
                    "-",
                    "-",
                ),
            }
            continue;
        }

        match Container::resolve(store, &container_name) {
            Some(mut c) => {
                c.refresh(store);
                let status = match c.status {
                    Status::Running => "running".to_string(),
                    Status::Exited(code) => format!("exited({code})"),
                };
                let health = if c.healthcheck.is_some() { c.health.as_str() } else { "-" };
                let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
                let stats = kiln_cli::cgroup::stats(&c.id);
                let cpu = stats
                    .as_ref()
                    .map(|s| (s.cpu_usage_usec / 1000).to_string())
                    .unwrap_or_else(|| "-".to_string());
                let mem = stats
                    .as_ref()
                    .map(|s| s.memory_current_bytes.to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<20}{:<14}{:<14}{:<11}{:<8}{:<10}{:<12}{}",
                    name,
                    &c.id[..12.min(c.id.len())],
                    status,
                    health,
                    pid,
                    cpu,
                    mem,
                    c.command.join(" ")
                );
            }
            None => println!("{:<20}{:<14}{:<14}{:<11}{:<8}{:<10}{:<12}", name, "-", "not created", "", "", "-", "-"),
        }
    }
    Ok(())
}

fn cmd_logs(store: &Store, project: &str, compose: &ComposeFile, follow: bool) -> CliResult {
    let mut remote_tails: Vec<RemoteTail> = Vec::new();
    let mut any_remote_found = false;

    for (name, svc) in &compose.services {
        let Some(node_name) = &svc.node else { continue };
        let container_name = format!("{project}_{name}");
        let Some(node) = kiln_cli::commands::node::find_node(store, node_name) else {
            eprintln!("kiln-compose: {name}: no such node: {node_name}");
            continue;
        };
        any_remote_found = true;
        if follow {
            remote_tails.push(RemoteTail {
                display_name: name.clone(),
                node,
                container_name,
            });
            continue;
        }
        match remote::logs(&node, &container_name) {
            Ok(content) => {
                for line in content.lines() {
                    println!("{name} | {line}");
                }
            }
            Err(e) => eprintln!("kiln-compose: fetching logs for {name} on {node_name}: {e}"),
        }
    }

    let containers: Vec<Container> = compose
        .services
        .iter()
        .filter(|(_, svc)| svc.node.is_none())
        .filter_map(|(name, _)| Container::resolve(store, &format!("{project}_{name}")))
        .collect();

    if containers.is_empty() && !any_remote_found {
        println!("no containers for this project - run `kiln-compose up` first");
        return Ok(());
    }

    if follow {
        stream_aggregated_logs(store, &containers, &remote_tails, false)
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

/// A node-tagged service to tail remotely - `stream_aggregated_logs`'s
/// equivalent of a local `Container` entry, since a remote service has
/// no local `Container` state to read a log path out of at all (see
/// `remote::logs_follow`'s own docs on the streaming mechanism this
/// drives).
struct RemoteTail {
    display_name: String,
    node: kiln_cli::commands::node::Node,
    container_name: String,
}

/// Tail every container's log concurrently, each line prefixed with its
/// service name, until Ctrl-C. If `own_containers` (true only for `up`'s
/// own foreground mode, never for `logs -f`), Ctrl-C also stops every
/// container - local ones via SIGTERM to their pid, remote ones via
/// `remote::stop_container` - mirroring `docker-compose up`'s "foreground
/// is the lifetime" behavior; `kiln-compose logs -f` just detaches from
/// watching without touching anything.
fn stream_aggregated_logs(store: &Store, containers: &[Container], remote_tails: &[RemoteTail], own_containers: bool) -> CliResult {
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

    for rt in remote_tails {
        let display_name = rt.display_name.clone();
        let node = rt.node.clone();
        let container_name = rt.container_name.clone();
        handles.push(std::thread::spawn(move || {
            use std::io::Read;
            let mut reader = match remote::logs_follow(&node, &container_name) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("kiln-compose: {display_name}: {e}");
                    return;
                }
            };
            let mut buf = [0u8; 4096];
            let mut leftover = String::new();
            while !STOP.load(Ordering::SeqCst) {
                match reader.read(&mut buf) {
                    // Connection closed - the remote container exited, or
                    // kilnd's own follow loop ended for the same reason a
                    // local one would (see kilnd's containers::logs).
                    Ok(0) => break,
                    Ok(n) => {
                        leftover.push_str(&String::from_utf8_lossy(&buf[..n]));
                        while let Some(idx) = leftover.find('\n') {
                            let line = leftover[..idx].to_string();
                            leftover.drain(..=idx);
                            println!("{display_name} | {line}");
                        }
                    }
                    // The read timeout `logs_follow` sets is exactly what
                    // lets this loop notice `STOP` promptly instead of
                    // blocking indefinitely for the remote side to write
                    // more output - not a real error.
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    Err(_) => break,
                }
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
        for rt in remote_tails {
            let _ = remote::stop_container(&rt.node, &rt.container_name);
        }
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
