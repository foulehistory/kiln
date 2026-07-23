//! `kiln inspect` - full JSON dump of a container or image, for scripting
//! or debugging beyond what `kiln ps`/`kiln images`'s fixed-column tables
//! show. `--security` narrows a container's output to just its
//! seccomp/capability profile - the *requested* profile alone (the raw
//! `Container` dump's `security` field) only shows what was asked for,
//! not what a running container actually ended up with.

use crate::container::{Container, Status};
use crate::error::{CliError, CliResult};
use kiln_image::image::Image;
use kiln_image::store::Store;
use kilnd_core::security;
use serde::Serialize;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// A container id/name, or an image reference/id
    pub target: String,
    /// Show only the effective seccomp/capability profile (container
    /// targets only) - see `kilnd_core::security`'s own docs on what
    /// "effective" means here.
    #[arg(long)]
    pub security: bool,
    /// Show only configured resource limits alongside live cgroup usage
    /// (container targets only) - see `ResourcesReport`.
    #[arg(long)]
    pub resources: bool,
}

/// Also reused directly by `kilnd`'s `GET /containers/:id/security`
/// handler, so the CLI and the HTTP API report identical data - see
/// `kilnd::handlers::containers::security`.
#[derive(Serialize)]
pub struct SecurityReport {
    /// `"unconfined"` or `"enforced (allow-list)"`.
    pub seccomp: String,
    /// Baseline plus `cap_add`, minus `cap_drop`, resolved to concrete
    /// capability names - see `kilnd_core::security::effective_capabilities`.
    pub effective_capabilities: Vec<String>,
    /// `/proc/<pid>/status`'s real `CapBnd:`, decoded - only available
    /// for a currently-running container; `None` for a stopped one (its
    /// process, and hence this data, no longer exists).
    pub live_capability_bounding_set: Option<Vec<String>>,
    /// `false` only if `live_capability_bounding_set` was read and
    /// doesn't match `effective_capabilities` exactly - which would mean
    /// something other than `drop_capabilities` changed this process's
    /// bounding set after startup. `true` when there's nothing live to
    /// check (container not running) or the two sets agree.
    pub matches_expected: bool,
}

pub fn security_report(c: &Container) -> SecurityReport {
    let effective: Vec<String> = security::effective_capabilities(&c.security)
        .map(|set| {
            let mut names: Vec<String> = set.iter().map(|cap| cap.to_string()).collect();
            names.sort();
            names
        })
        .unwrap_or_default();

    let live = if c.status == Status::Running {
        c.pid.and_then(|pid| security::read_capability_bounding_set(pid).ok()).map(|mask| {
            let mut names: Vec<String> = security::decode_capability_set(mask).iter().map(|cap| cap.to_string()).collect();
            names.sort();
            names
        })
    } else {
        None
    };

    let matches_expected = live.as_ref().is_none_or(|live| live == &effective);

    SecurityReport {
        seccomp: if c.security.seccomp_unconfined {
            "unconfined".to_string()
        } else {
            "enforced (allow-list)".to_string()
        },
        effective_capabilities: effective,
        live_capability_bounding_set: live,
        matches_expected,
    }
}

/// Also reused directly by `kilnd`'s `GET /containers/:id/resources`
/// handler - see `security_report`'s own docs on the same pattern.
#[derive(Serialize)]
pub struct ResourcesReport {
    /// `None` for any field below means "unlimited", exactly like a plain
    /// `kiln run` with no `--memory`/`--cpus`/`resources:` given.
    pub cpu_limit: Option<f64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_swap_bytes: Option<u64>,
    /// The derived soft-throttle threshold (`memory.high`, ~90% of
    /// `memory_limit_bytes`) - see `kilnd_core::cgroups::Limits::memory_high_bytes`'s
    /// own docs. `None` whenever there's no memory limit to derive it from.
    pub memory_high_bytes: Option<u64>,
    /// Live cgroup usage - `None` if the container has no cgroup (never
    /// started, or removed).
    pub live: Option<crate::cgroup::Stats>,
    /// Whether the container's *last* exit was an OOM-kill - see
    /// `Container::last_exit_oom_killed`'s own docs. Still `true` after
    /// a container has since been restarted successfully, until its next
    /// exit overwrites it - a historical fact about the last run, not a
    /// live condition.
    pub last_exit_oom_killed: bool,
}

pub fn resources_report(c: &Container) -> ResourcesReport {
    ResourcesReport {
        cpu_limit: c.cpu_limit,
        memory_limit_bytes: c.memory_limit_bytes,
        memory_swap_bytes: c.memory_swap_bytes,
        memory_high_bytes: c.memory_limit_bytes.map(|b| (b as f64 * 0.9) as u64),
        live: crate::cgroup::stats(&c.id),
        last_exit_oom_killed: c.last_exit_oom_killed,
    }
}

pub fn run(store: &Store, args: Args) -> CliResult {
    if let Some(mut c) = Container::resolve(store, &args.target) {
        c.refresh(store);
        if args.security {
            let report = security_report(&c);
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| CliError::msg(e.to_string()))?);
        } else if args.resources {
            let report = resources_report(&c);
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| CliError::msg(e.to_string()))?);
        } else {
            println!("{}", serde_json::to_string_pretty(&c).map_err(|e| CliError::msg(e.to_string()))?);
        }
        return Ok(());
    }
    if let Ok(image) = Image::resolve(store, &args.target) {
        if args.security {
            return Err(CliError::msg("--security only applies to containers, not images"));
        }
        if args.resources {
            return Err(CliError::msg("--resources only applies to containers, not images"));
        }
        println!("{}", serde_json::to_string_pretty(&image).map_err(|e| CliError::msg(e.to_string()))?);
        return Ok(());
    }
    Err(CliError::msg(format!("no such container or image: {}", args.target)))
}
