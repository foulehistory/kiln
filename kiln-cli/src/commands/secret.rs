//! `kiln secret` - encrypted-at-rest values, mounted into a container as
//! a file (`/run/secrets/<name>`) rather than a plain `-e` environment
//! variable, which `kiln inspect`/`Container`'s own persisted state would
//! otherwise show in the clear forever. See `kiln_image::secrets` for the
//! actual encryption.

use crate::container::{Container, Status};
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use kilnd_core::namespaces::join_namespaces;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult};
use rand::RngCore;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Create (or overwrite) a secret. The value is read from stdin,
    /// never a command-line argument - a positional value would end up
    /// in shell history. e.g. `echo -n "hunter2" | kiln secret create
    /// admin-password`
    #[command(alias = "set")]
    Create {
        name: String,
        /// An informative expiration marker only (e.g. `30d`, `12h`) -
        /// nothing rotates automatically once it passes; surfaced by
        /// `kiln secret ls`/the dashboard purely so an operator notices
        /// and rotates by hand. Accepts a bare integer (seconds), or a
        /// number suffixed with `s`/`m`/`h`/`d`/`w`.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// List secret names - never values
    Ls,
    Rm {
        name: String,
    },
    /// Re-encrypt an existing secret's value under a fresh nonce (same
    /// local master key as `create` used) and bump its version. Exactly
    /// one of `--value`/`--generate` may be given; if neither is, the new
    /// value is read from stdin, same convention as `create`.
    ///
    /// Any container currently running with this secret mounted has its
    /// live `/run/secrets/<name>` tmpfs file updated in place (see
    /// `update_live_secret_mounts`'s own docs on how, and the one case
    /// where that isn't possible) - no restart needed for those. A
    /// container that is *not* currently running picks up the new value
    /// the next time it's started (`kiln start`/`kiln-compose up`
    /// re-decrypt `<name>.enc` from scratch at that point, same as any
    /// other secret).
    Rotate {
        name: String,
        /// New value, given directly rather than via stdin - be aware
        /// this puts the value in your shell's history/process list,
        /// unlike `create`'s stdin-only default.
        #[arg(long, conflicts_with = "generate")]
        value: Option<String>,
        /// Generate a random new value instead of supplying one - printed
        /// once, since there's otherwise no way to know what it is (this
        /// project has no "get secret value" command by design).
        #[arg(long)]
        generate: bool,
    },
}

/// 24 random bytes, hex-encoded (48 characters) - same entropy class as
/// the local master key itself (`kiln_image::secrets`'s own
/// `load_or_create_master_key`), reused for `kiln secret rotate
/// --generate` and the dashboard's "Rotate" button (which always
/// generates, never prompts for a value - see `kilnd`'s
/// `handlers::secrets::rotate`).
pub fn generate_value() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Parses a Compose-style single-unit duration (`30d`, `12h`, `10m`,
/// `45s`, or a bare integer meaning seconds) into seconds. Deliberately
/// not a full duration grammar (no compound units like `1d12h`) - good
/// enough for an informative TTL marker, not meant to be a general
/// parser. Adds a `w` (week) suffix on top of
/// `kiln_compose`'s own `parse_duration_secs`, since a secret's rotation
/// cadence is much more likely to be measured in weeks than a
/// healthcheck's interval/timeout ever would be - kept local rather than
/// shared for that reason.
fn parse_ttl_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.ends_with("ms") {
        return Err(format!("invalid duration {s:?}: sub-second (ms) durations aren't supported"));
    }
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60u64),
        Some('h') => (&s[..s.len() - 1], 3600u64),
        Some('d') => (&s[..s.len() - 1], 86_400u64),
        Some('w') => (&s[..s.len() - 1], 604_800u64),
        _ => (s, 1u64),
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("invalid duration {s:?}: expected e.g. 30d, 12h, 10m, 45s, or a plain second count"))
}

fn read_value_from_stdin() -> CliResult<Vec<u8>> {
    let mut value = Vec::new();
    std::io::stdin().read_to_end(&mut value).map_err(CliError::from)?;
    // A trailing newline from `echo "..." | kiln secret ...` is almost
    // never intended to be part of the secret itself - `echo -n`/`printf`
    // avoid it, but stripping one trailing `\n` (and a `\r\n` on top of
    // it) is a much friendlier default than making every caller remember
    // `-n`.
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err(CliError::msg("secret value must not be empty (nothing read from stdin)"));
    }
    Ok(value)
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Create { name, ttl } => {
            let ttl_secs = ttl.as_deref().map(parse_ttl_secs).transpose().map_err(CliError::msg)?;
            let value = read_value_from_stdin()?;
            kiln_image::secrets::create(store.root(), &name, &value, ttl_secs)?;
            println!("{name}");
        }
        Command::Ls => {
            println!("{:<24}{:<9}{:<22}TTL", "SECRET NAME", "VERSION", "LAST ROTATED");
            for name in kiln_image::secrets::list(store.root()) {
                match kiln_image::secrets::meta(store.root(), &name) {
                    Some(m) => {
                        let last_rotated = m.rotated_at.map(format_unix).unwrap_or_else(|| "(never)".to_string());
                        let ttl = match (m.ttl_secs, m.expires_at()) {
                            (Some(_), Some(expires_at)) if expires_at <= now_unix() => "EXPIRED".to_string(),
                            (Some(secs), _) => format_duration(secs),
                            (None, _) => "-".to_string(),
                        };
                        println!("{:<24}{:<9}{:<22}{}", name, m.version, last_rotated, ttl);
                    }
                    None => println!("{:<24}{:<9}{:<22}-", name, "-", "-"),
                }
            }
        }
        Command::Rm { name } => {
            kiln_image::secrets::remove(store.root(), &name)?;
            println!("{name}");
        }
        Command::Rotate { name, value, generate } => {
            let (new_value, generated) = if generate {
                let v = generate_value();
                (v.clone().into_bytes(), Some(v))
            } else if let Some(v) = value {
                (v.into_bytes(), None)
            } else {
                (read_value_from_stdin()?, None)
            };

            let meta = kiln_image::secrets::rotate(store.root(), &name, &new_value)?;

            let updates = update_live_secret_mounts(store, &name, &new_value);
            println!("{name} rotated to version {}", meta.version);
            if updates.is_empty() {
                println!("(no running containers have this secret mounted)");
            }
            for u in &updates {
                if u.updated {
                    println!(
                        "  {} ({}): live tmpfs mount updated, no restart needed",
                        u.container_name,
                        &u.container_id[..12.min(u.container_id.len())]
                    );
                } else {
                    println!(
                        "  {} ({}): PENDING RESTART - could not update the live mount, restart to apply the new value",
                        u.container_name,
                        &u.container_id[..12.min(u.container_id.len())]
                    );
                }
            }
            if let Some(v) = generated {
                println!("generated value (shown once - this project has no way to display it again): {v}");
            }
        }
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_unix(t: u64) -> String {
    let ago = now_unix().saturating_sub(t);
    format!("{} ago", format_duration(ago))
}

fn format_duration(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

pub struct LiveUpdateResult {
    pub container_id: String,
    pub container_name: String,
    pub updated: bool,
}

/// Best-effort: writes `new_value` directly into `/run/secrets/<name>`
/// inside the mount namespace of every currently-*running* container
/// that has `name` in its own `secrets` list, so an already-running
/// container picks up the rotated value without needing a restart - the
/// tmpfs `mount_tmpfs_secrets` originally populated (see
/// `kilnd_core::rootfs`'s own docs) is a real, live mount, and root can
/// write into it from the host by joining that container's `user`+`mnt`
/// namespaces, the same `setns(2)` recipe `kiln cp`'s host-to-container
/// direction already relies on (see `cp.rs`'s own module docs for why
/// that's the one write path that actually works against this project's
/// overlayfs/WSL2 combination).
///
/// This is genuinely live - not a "mark pending, apply on next restart"
/// placeholder - for every container this succeeds against. `updated:
/// false` in the returned list is the one honest exception: if joining
/// namespaces or writing the file fails for some reason (a container
/// that raced to exit between being listed here and the write, a
/// permissions surprise), that specific container is left running on
/// its old value and genuinely does need a restart to pick up the
/// rotated one - reported as such, never silently swallowed.
///
/// A container that is *stopped* isn't touched at all: it has no
/// `/proc/<pid>` to join into, and it'll re-decrypt the (already
/// rotated) `<name>.enc` fresh the next time it's started anyway.
pub fn update_live_secret_mounts(store: &Store, name: &str, new_value: &[u8]) -> Vec<LiveUpdateResult> {
    Container::list(store)
        .into_iter()
        .filter_map(|mut c| {
            c.refresh(store);
            if c.status != Status::Running || !c.secrets.iter().any(|s| s == name) {
                return None;
            }
            let updated = update_live_secret_mount(&c, name, new_value).is_ok();
            Some(LiveUpdateResult {
                container_id: c.id.clone(),
                container_name: c.name.clone(),
                updated,
            })
        })
        .collect()
}

/// Writes `new_value` to `/run/secrets/<name>` inside `container`'s own
/// mount namespace, in a forked child that joins it (mirrors `cp.rs`'s
/// `write_into_container`, minus the host-file-read side since the value
/// is already in memory here).
fn update_live_secret_mount(container: &Container, name: &str, new_value: &[u8]) -> Result<(), String> {
    let pid = nix::unistd::Pid::from_raw(container.pid.ok_or("container has no pid")?);
    let (read_end, write_end) = nix::unistd::pipe().map_err(|e| format!("pipe: {e}"))?;

    match unsafe { fork() }.map_err(|e| format!("fork: {e}"))? {
        ForkResult::Parent { child } => {
            drop(read_end);
            let mut io_err = None;
            if let Err(e) = nix::unistd::write(&write_end, new_value) {
                io_err = Some(format!("writing to pipe: {e}"));
            }
            drop(write_end);
            let status = waitpid(child, None).map_err(|e| format!("waitpid: {e}"))?;
            if let Some(e) = io_err {
                return Err(e);
            }
            match status {
                WaitStatus::Exited(_, 0) => Ok(()),
                other => Err(format!("child exited abnormally: {other:?}")),
            }
        }
        ForkResult::Child => {
            drop(write_end);
            let outcome: Result<(), String> = (|| {
                join_namespaces(pid, &["user", "mnt"]).map_err(|e| format!("join_namespaces: {e}"))?;
                nix::unistd::setgroups(&[]).map_err(|e| format!("setgroups: {e}"))?;
                nix::unistd::setresgid(
                    nix::unistd::Gid::from_raw(0),
                    nix::unistd::Gid::from_raw(0),
                    nix::unistd::Gid::from_raw(0),
                )
                .map_err(|e| format!("setresgid: {e}"))?;
                nix::unistd::setresuid(
                    nix::unistd::Uid::from_raw(0),
                    nix::unistd::Uid::from_raw(0),
                    nix::unistd::Uid::from_raw(0),
                )
                .map_err(|e| format!("setresuid: {e}"))?;
                let path = format!("/run/secrets/{name}");
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 65536];
                    let n = nix::unistd::read(read_end.as_raw_fd(), &mut chunk).map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                std::fs::write(&path, &buf).map_err(|e| format!("writing {path}: {e}"))?;
                // Same mode `mount_tmpfs_secrets` originally wrote the
                // file with - keep it consistent rather than whatever
                // the container's umask would otherwise leave it at.
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).map_err(|e| format!("chmod {path}: {e}"))?;
                Ok(())
            })();
            match outcome {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    // Deliberately not the secret value itself - only the
                    // *mechanism* failure (join_namespaces/write/chmod
                    // error text never includes file contents).
                    eprintln!("kiln: updating live secret mount: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
