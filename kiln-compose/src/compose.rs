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
    #[serde(default)]
    pub depends_on: Vec<String>,
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
        for dep in &svc.depends_on {
            if !services.contains_key(dep) {
                return Err(format!("service {name:?} depends_on unknown service {dep:?}"));
            }
        }
    }

    let mut remaining: BTreeMap<&String, usize> =
        services.iter().map(|(name, svc)| (name, svc.depends_on.len())).collect();
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
            *count = services[*name].depends_on.iter().filter(|d| !order.contains(d)).count();
        }
    }

    if order.len() != services.len() {
        let stuck: Vec<&str> = remaining.keys().map(|s| s.as_str()).collect();
        return Err(format!("circular depends_on among: {}", stuck.join(", ")));
    }

    Ok(order)
}
