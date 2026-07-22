//! Persisted state for containers created with `kiln run`.
//!
//! Unlike images/layers, a container is not content-addressed - it's
//! mutable, ephemeral runtime state (is it running? what's its pid? what
//! did it exit with?). It's still stored under the same [`Store`] though,
//! at `containers/<id>/`, alongside its own writable overlay layer
//! (`upper`/`work`/`merged`) and log file, so a single `--store` path is
//! all `kiln` ever needs to know about.

use kiln_image::store::{Hash, Store};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    Running,
    Exited(i32),
}

/// `--restart`. Checked by the per-container supervisor right before it
/// would otherwise exit after recording the container's exit code - see
/// `supervisor.rs`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    #[default]
    No,
    Always,
    OnFailure,
}

impl RestartPolicy {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "no" => Ok(RestartPolicy::No),
            "always" => Ok(RestartPolicy::Always),
            "on-failure" => Ok(RestartPolicy::OnFailure),
            other => Err(format!("invalid --restart {other:?}: expected no, always, or on-failure")),
        }
    }

    pub fn should_restart(self, exit_code: i32) -> bool {
        match self {
            RestartPolicy::No => false,
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => exit_code != 0,
        }
    }
}

/// `--health-cmd`/`--health-interval`/`--health-timeout`/`--health-retries`,
/// or `healthcheck:` in `kiln.yaml` - persisted on [`Container`] (like
/// `restart_policy`) so `kiln start`/the restart-policy path in
/// `supervisor.rs` keep probing the same command after a restart, not
/// just on the run that first specified it. Probing itself is done by
/// `crate::healthcheck::run_loop`, on a background thread the supervisor
/// spawns alongside its own `waitpid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckSpec {
    /// Exec-array form only (`["curl", "-f", "http://localhost/"]`) -
    /// `kiln-compose`'s `healthcheck.test` expands Compose's `CMD`/
    /// `CMD-SHELL`/bare-string forms down to this before it reaches here.
    pub test: Vec<String>,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    /// Consecutive failures required before `health` flips to
    /// `Unhealthy` - a single blip leaves the last-known status alone,
    /// matching Docker's own `retries` semantics.
    pub retries: u32,
}

impl HealthCheckSpec {
    pub const DEFAULT_INTERVAL_SECS: u64 = 30;
    pub const DEFAULT_TIMEOUT_SECS: u64 = 5;
    pub const DEFAULT_RETRIES: u32 = 3;
}

/// Health status as reported by the healthcheck probe loop - independent
/// of `Status` (running/exited): a container can be `Running` and
/// `Unhealthy` at the same time. `Starting` is the state for the entire
/// time no probe has yet completed (including containers with no
/// `healthcheck` configured at all - there's simply never anything to
/// transition it away from `Starting` in that case).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum HealthStatus {
    #[default]
    Starting,
    Healthy,
    Unhealthy,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Starting => "starting",
            HealthStatus::Healthy => "healthy",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image_reference: String,
    pub image_id: Hash,
    pub command: Vec<String>,
    /// Host pid of the container's PID-1 process, once known. Set by the
    /// per-container supervisor once `spawn_paused` returns a real pid -
    /// see `supervisor.rs`.
    pub pid: Option<i32>,
    pub status: Status,
    pub created_at: u64,
    /// IP address on its attached network, if any - set by the
    /// per-container supervisor after `commands::network::attach_container`
    /// succeeds. Used by `kiln-compose` for its `/etc/hosts`-based
    /// service discovery (see `commands::run::RunSpec::extra_hosts`).
    #[serde(default)]
    pub ip: Option<String>,
    /// Name of the network `ip` belongs to, if any - lets `kilnd`'s
    /// dashboard API group containers by network for a topology view
    /// without having to cross-reference every network's own state.
    #[serde(default)]
    pub network: Option<String>,
    /// The `-v <volume>:<path>` mounts and extra environment variables
    /// this container was started with - not needed for a first `kiln
    /// run`, but required to reproduce the same launch on `kiln start`
    /// (restarting a stopped container) without asking the caller to
    /// re-supply them. `#[serde(default)]` so state.json written before
    /// these fields existed still deserializes (as "none", the closest
    /// approximation for a container that predates `restart` entirely).
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// `--memory`/`--cpus`, persisted for the same reason as `volumes`/`env`
    /// above - so `kiln start` reapplies the same limits instead of
    /// silently reverting to unlimited.
    #[serde(default)]
    pub memory_limit_bytes: Option<u64>,
    #[serde(default)]
    pub cpu_limit: Option<f64>,
    /// `-p`/`--publish` specs this container was started with - persisted
    /// for the same restart-fidelity reason as `volumes`/`env` above. No
    /// separate cleanup step reads this back: the port-forwarding relay's
    /// lifetime is tied directly to the supervisor process (see
    /// `network::spawn_port_forwarder`'s docs), not tracked here.
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// Names of secrets (`--secret <name>`) mounted at `/run/secrets/` -
    /// same restart-fidelity role as `volumes`/`env`, but names only,
    /// never a value: unlike `env`, this field is safe to persist and
    /// show (e.g. in `kiln inspect`) as-is.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Seccomp/capability overrides this container was started with -
    /// same restart-fidelity role as the fields above. See
    /// `kilnd_core::security::SecurityProfile`'s own docs.
    #[serde(default)]
    pub security: kilnd_core::security::SecurityProfile,
    /// The healthcheck command this container was started with, if any -
    /// same restart-fidelity role as `security`/`secrets` above.
    #[serde(default)]
    pub healthcheck: Option<HealthCheckSpec>,
    /// Last-probed health status - see [`HealthStatus`]. Reset to
    /// `Starting` every time this container (re)starts, updated by
    /// `crate::healthcheck::run_loop` from then on.
    #[serde(default)]
    pub health: HealthStatus,
    /// Consecutive automatic restarts since the last time this container
    /// ran long enough to be considered stable - drives the exponential
    /// backoff in `supervisor.rs`. Not part of `RunSpec`: this is
    /// supervisor-owned bookkeeping, never something a caller sets
    /// directly, only read/incremented across a restart-policy-triggered
    /// relaunch.
    #[serde(default)]
    pub restart_count: u32,
    /// Unix timestamp of the most recent successful start - used to
    /// decide whether a crash counts as part of an ongoing crash loop
    /// (reset `restart_count`) or a fresh one. Supervisor-owned, like
    /// `restart_count`.
    #[serde(default)]
    pub last_started_at: Option<u64>,
}

impl Container {
    pub fn dir(store: &Store, id: &str) -> PathBuf {
        store.containers_dir().join(id)
    }
    pub fn state_path(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("state.json")
    }
    pub fn log_path(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("log")
    }
    pub fn upper_dir(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("upper")
    }
    pub fn work_dir(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("work")
    }
    pub fn merged_dir(store: &Store, id: &str) -> PathBuf {
        Self::dir(store, id).join("merged")
    }

    pub fn save(&self, store: &Store) -> kiln_image::Result<()> {
        store.write_json(&Self::state_path(store, &self.id), self)
    }

    pub fn load(store: &Store, id: &str) -> Option<Container> {
        store.read_json(&Self::state_path(store, id)).ok()
    }

    pub fn list(store: &Store) -> Vec<Container> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(store.containers_dir()) {
            for entry in entries.flatten() {
                if let Some(id) = entry.file_name().to_str() {
                    if let Some(c) = Container::load(store, id) {
                        out.push(c);
                    }
                }
            }
        }
        out.sort_by_key(|c| c.created_at);
        out
    }

    /// Look a container up by exact id, exact name, or id prefix (like
    /// `git` short hashes) - whatever the user typed on the command line.
    pub fn resolve(store: &Store, id_or_name: &str) -> Option<Container> {
        if let Some(c) = Container::load(store, id_or_name) {
            return Some(c);
        }
        let mut matches: Vec<Container> = Container::list(store)
            .into_iter()
            .filter(|c| c.name == id_or_name || c.id.starts_with(id_or_name))
            .collect();
        if matches.len() == 1 {
            matches.pop()
        } else {
            None
        }
    }

    /// If we think this container is `Running`, confirm the pid is still
    /// alive; if it isn't (e.g. it was killed while no `kiln` process was
    /// around to observe it via the normal supervisor path - see
    /// `supervisor.rs`), mark it `Exited` with an unknown (`-1`) code
    /// rather than continuing to report a dead process as running.
    pub fn refresh(&mut self, store: &Store) {
        if self.status == Status::Running {
            let alive = self
                .pid
                .map(|pid| nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok())
                .unwrap_or(false);
            if !alive {
                self.status = Status::Exited(-1);
                let _ = self.save(store);
            }
        }
    }
}

pub fn generate_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
