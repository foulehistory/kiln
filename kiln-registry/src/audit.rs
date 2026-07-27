//! An append-only log of every push/pull/admin action this registry has
//! authorized (or refused) - one JSON line per event, in the same
//! newline-delimited-JSON style `kiln`'s own container logs don't use but
//! is the simplest thing that's both trivially appendable (never needs
//! to rewrite earlier entries) and trivially greppable/parseable later.
//!
//! Deliberately minimal: timestamp, account, action, resource, and
//! whether it was allowed - never the credentials themselves (a Bearer
//! token or password never appears here, only the *account* a token was
//! already resolved to by the time `handlers::authorize` calls this).

use crate::store::RegistryStore;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub username: String,
    pub action: String,
    pub resource: String,
    pub allowed: bool,
}

/// Best-effort: a logging failure (disk full, permissions) must never
/// fail the request it's describing - the registry keeps serving either
/// way, same reasoning as `kilnd`'s own log-write failures elsewhere in
/// this workspace.
pub fn log(store: &RegistryStore, username: &str, action: &str, resource: &str, allowed: bool) {
    let entry = Entry {
        ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        username: username.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        allowed,
    };
    let Ok(mut line) = serde_json::to_vec(&entry) else { return };
    line.push(b'\n');
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(store.audit_log_path()) {
        let _ = f.write_all(&line);
    }
}

/// Reads every entry back, oldest first - `kiln-registry audit`'s own
/// filtering (`--user`/`--action`/`--denied-only`) happens on top of
/// this, not here, so this stays a plain, total read of whatever's on
/// disk.
pub fn read_all(store: &RegistryStore) -> Vec<Entry> {
    let Ok(contents) = std::fs::read_to_string(store.audit_log_path()) else {
        return Vec::new();
    };
    contents.lines().filter_map(|line| serde_json::from_str(line).ok()).collect()
}
