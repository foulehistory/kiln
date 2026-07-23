//! Parsing for `kiln.yaml`: a small, `docker-compose.yml`-shaped format
//! (`services`, `volumes`, `networks`, `depends_on`). Deliberately not a
//! drop-in Compose-spec implementation - just the subset that maps
//! directly onto what `kiln run` already supports.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Default)]
pub struct ComposeFile {
    #[serde(default)]
    pub services: BTreeMap<String, Service>,
    #[serde(default)]
    pub volumes: BTreeMap<String, serde_yaml::Value>,
    /// Declares secret *names* only - same role as `volumes` above: the
    /// real value never lives in `kiln.yaml`, only created out-of-band
    /// via `kiln secret create`. Parsed so a `secrets:` section doesn't
    /// fail to parse; `cmd_up` doesn't need to iterate this directly
    /// (each service's own `secrets:` list is what actually gets mounted).
    #[serde(default)]
    #[allow(dead_code)]
    pub secrets: BTreeMap<String, serde_yaml::Value>,
    /// Parsed but not yet acted on: v1 always attaches every service to
    /// one implicit `<project>_default` network (see `main.rs::cmd_up`)
    /// rather than supporting custom network topologies. Kept as a field
    /// so a `networks:` section in `kiln.yaml` doesn't fail to parse.
    #[serde(default)]
    #[allow(dead_code)]
    pub networks: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Service {
    pub image: Option<String>,
    /// Path (relative to the compose file) to a build context containing
    /// a `Kilnfile`.
    pub build: Option<String>,
    #[serde(default)]
    pub command: Option<CommandField>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// `<volume>:<path>` entries, same syntax as `kiln run -v`.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// `<host>:<container>[/tcp|udp]` entries, same syntax as `kiln run
    /// -p` - see `kiln_cli::commands::network::PortSpec`.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Names of secrets (declared in the top-level `secrets:` map,
    /// created with `kiln secret create`) to mount at `/run/secrets/` -
    /// same syntax/role as `kiln run --secret`.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Either the short list form (`depends_on: [db, cache]`, meaning
    /// `condition: service_started` for each - true as soon as the
    /// dependency's container exists and is running, regardless of any
    /// `healthcheck:` it may have) or Compose's own map form
    /// (`depends_on: { db: { condition: service_healthy } }`) - see
    /// `DependsOn`'s own docs.
    #[serde(default)]
    pub depends_on: DependsOn,
    /// Name of a `kiln node`-registered remote host to run this service
    /// on instead of locally - absent means local, same as today. See
    /// `main.rs`'s `resolve_service_image`/`cmd_up` for the dispatch
    /// logic, and `kiln-cli/src/commands/node.rs` for the registry this
    /// name is looked up in.
    #[serde(default)]
    pub node: Option<String>,
    /// Only `["seccomp:unconfined"]` is recognized (matches Docker
    /// Compose's own field name/syntax) - disables the default seccomp
    /// filter for this service. Never on by default; see
    /// `kilnd_core::security`'s own docs on the default profile this
    /// opts out of.
    #[serde(default)]
    pub security_opt: Vec<String>,
    /// Capabilities to add on top of the default baseline, e.g.
    /// `[NET_ADMIN]` - same syntax as `kiln run --cap-add`.
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// Capabilities to remove from the default baseline - same syntax as
    /// `kiln run --cap-drop`, checked after `cap_add`.
    #[serde(default)]
    pub cap_drop: Vec<String>,
    /// `"no"` (default if omitted), `"always"`, or `"on-failure"` - same
    /// syntax as `kiln run --restart`. See `kiln_cli::container::RestartPolicy`.
    #[serde(default)]
    pub restart: Option<String>,
    /// Docker Compose-shaped `healthcheck:` block - see `Healthcheck::into_spec`.
    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,
    /// `resources:` block (`cpu`/`memory`/`memory-swap`) - see
    /// `Resources::into_limits`. Absent means unlimited, same as a plain
    /// `kiln run` with no `--memory`/`--cpus` - existing stacks without
    /// this field keep running exactly as before.
    #[serde(default)]
    pub resources: Option<Resources>,
}

/// `resources:` in `kiln.yaml` - Docker Compose calls this
/// `deploy.resources.limits`, but Kiln isn't a swarm/orchestrator, so it's
/// flattened to a plain per-service `resources:` block instead. Fields use
/// the same Docker-style size suffixes (`k`/`m`/`g`) as `kiln run
/// --memory`/`--memory-swap` - see `kiln_cli::commands::run::parse_size`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Resources {
    /// Number of CPUs, e.g. `"0.5"` for half a core - same meaning as
    /// `kiln run --cpus`.
    #[serde(default)]
    pub cpu: Option<String>,
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default, rename = "memory-swap")]
    pub memory_swap: Option<String>,
}

/// Parsed form of `Resources`, matching the three separate fields
/// `RunSpec`/remote `RunRequest` already take.
pub struct ParsedResources {
    pub cpu_limit: Option<f64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_swap_bytes: Option<u64>,
}

impl Resources {
    pub fn parse(&self) -> Result<ParsedResources, String> {
        let cpu_limit = self
            .cpu
            .as_deref()
            .map(|s| {
                s.parse::<f64>()
                    .map_err(|_| format!("invalid cpu {s:?}: expected a number, e.g. \"0.5\""))
            })
            .transpose()?;
        let memory_limit_bytes = self.memory.as_deref().map(kiln_cli::commands::run::parse_size).transpose()?;
        let memory_swap_bytes = self.memory_swap.as_deref().map(kiln_cli::commands::run::parse_size).transpose()?;
        Ok(ParsedResources {
            cpu_limit,
            memory_limit_bytes,
            memory_swap_bytes,
        })
    }
}

/// `depends_on:` in `kiln.yaml` - either the short list form or Compose's
/// own map form with a per-dependency `condition:`. `Default` (an empty
/// list) is what a service with no `depends_on:` key at all gets.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum DependsOn {
    List(Vec<String>),
    Map(BTreeMap<String, DependsOnEntry>),
}

impl Default for DependsOn {
    fn default() -> Self {
        DependsOn::List(Vec::new())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DependsOnEntry {
    #[serde(default)]
    pub condition: DependsOnCondition,
}

/// `service_started` (the default, and the *only* meaning the short list
/// form ever has - true as soon as the dependency's container exists and
/// is running) or `service_healthy` (only meaningful for a dependency
/// that itself has a `healthcheck:` - see `cmd_up`'s own
/// `wait_for_dependency_health`, which is where this is actually
/// enforced, not here).
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependsOnCondition {
    #[default]
    ServiceStarted,
    ServiceHealthy,
}

impl DependsOn {
    pub fn names(&self) -> Vec<String> {
        match self {
            DependsOn::List(v) => v.clone(),
            DependsOn::Map(m) => m.keys().cloned().collect(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            DependsOn::List(v) => v.len(),
            DependsOn::Map(m) => m.len(),
        }
    }

    /// `service_started` for every name in the short list form (it has no
    /// way to express anything else) - `service_healthy` only from the
    /// map form, and only for a name actually listed there.
    pub fn condition(&self, name: &str) -> DependsOnCondition {
        match self {
            DependsOn::List(_) => DependsOnCondition::ServiceStarted,
            DependsOn::Map(m) => m.get(name).map(|e| e.condition).unwrap_or_default(),
        }
    }
}

/// `healthcheck:` in `kiln.yaml` - deliberately just the Compose fields
/// that map onto `kiln_cli::container::HealthCheckSpec`; no `start_period`
/// (nothing here defers when `retries` starts counting).
#[derive(Debug, Deserialize, Clone)]
pub struct Healthcheck {
    pub test: HealthcheckTest,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub retries: Option<u32>,
}

/// Accepts Compose's `["CMD", ...]`/`["CMD-SHELL", "..."]`/bare-array
/// forms, or a bare shell string (Compose's implicit `CMD-SHELL`).
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum HealthcheckTest {
    Shell(String),
    Exec(Vec<String>),
}

impl Healthcheck {
    pub fn into_spec(self) -> Result<kiln_cli::container::HealthCheckSpec, String> {
        let test = match self.test {
            HealthcheckTest::Shell(s) => vec!["/bin/sh".to_string(), "-c".to_string(), s],
            HealthcheckTest::Exec(v) => match v.first().map(String::as_str) {
                Some("CMD-SHELL") => vec!["/bin/sh".to_string(), "-c".to_string(), v.get(1).cloned().unwrap_or_default()],
                Some("CMD") => v[1..].to_vec(),
                _ => v,
            },
        };
        if test.is_empty() {
            return Err("healthcheck.test must not be empty".to_string());
        }
        Ok(kiln_cli::container::HealthCheckSpec {
            test,
            interval_secs: self
                .interval
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(kiln_cli::container::HealthCheckSpec::DEFAULT_INTERVAL_SECS),
            timeout_secs: self
                .timeout
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(kiln_cli::container::HealthCheckSpec::DEFAULT_TIMEOUT_SECS),
            retries: self.retries.unwrap_or(kiln_cli::container::HealthCheckSpec::DEFAULT_RETRIES),
        })
    }
}

/// Parses a Compose-style single-unit duration (`10s`, `2m`, `1h`, or a
/// bare integer meaning seconds). Deliberately not the full Go duration
/// grammar Compose itself accepts - no compound units (`1m30s`) and no
/// sub-second precision (`500ms`); good enough for a healthcheck
/// interval/timeout, not meant to be a general parser.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.ends_with("ms") {
        return Err(format!(
            "invalid duration {s:?}: sub-second (ms) durations aren't supported, use whole seconds"
        ));
    }
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60u64),
        Some('h') => (&s[..s.len() - 1], 3600u64),
        _ => (s, 1u64),
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("invalid duration {s:?}: expected e.g. 10s, 2m, 1h, or a plain second count"))
}

/// Accepts either Compose's shell-string form (`command: "echo hi"`) or
/// its exec-array form (`command: ["echo", "hi"]`) - `kiln run` itself
/// only supports the array form, so the string form is expanded to
/// `["/bin/sh", "-c", <string>]` when read.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum CommandField {
    Shell(String),
    Exec(Vec<String>),
}

impl CommandField {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            CommandField::Shell(s) => vec!["/bin/sh".to_string(), "-c".to_string(), s],
            CommandField::Exec(v) => v,
        }
    }
}

pub fn parse(source: &str) -> Result<ComposeFile, serde_yaml::Error> {
    serde_yaml::from_str(source)
}

/// Order `services` so every service comes after everything in its
/// `depends_on` (Kahn's algorithm). Errors on an unknown dependency or a
/// cycle, naming exactly what's wrong rather than just "invalid graph".
pub fn dependency_order(services: &BTreeMap<String, Service>) -> Result<Vec<String>, String> {
    for (name, svc) in services {
        for dep in svc.depends_on.names() {
            if !services.contains_key(&dep) {
                return Err(format!("service {name:?} depends_on unknown service {dep:?}"));
            }
        }
    }

    let mut remaining: BTreeMap<&String, usize> = services.iter().map(|(name, svc)| (name, svc.depends_on.len())).collect();
    let mut order = Vec::with_capacity(services.len());

    loop {
        let ready: Vec<String> = remaining
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(name, _)| (*name).clone())
            .collect();
        if ready.is_empty() {
            break;
        }
        for name in &ready {
            remaining.remove(name);
            order.push(name.clone());
        }
        // Re-derive remaining counts: a dependency may have just been
        // satisfied by this batch.
        for (name, count) in remaining.iter_mut() {
            *count = services[*name].depends_on.names().iter().filter(|d| !order.contains(d)).count();
        }
    }

    if order.len() != services.len() {
        let stuck: Vec<&str> = remaining.keys().map(|s| s.as_str()).collect();
        return Err(format!("circular depends_on among: {}", stuck.join(", ")));
    }

    Ok(order)
}
