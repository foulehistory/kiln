//! `kiln-registry`: a self-hosted OCI Distribution registry server, so
//! one Kiln user can `kiln push` an image and another can `kiln pull`
//! the same reference (`<host>/<username>/<image>:<tag>`) - no
//! third-party registry account needed. See the module docs on
//! `handlers` for exactly which slice of the OCI Distribution API is
//! implemented.
//!
//! Unlike `kilnd` (loopback-only, a local dashboard backend), this is
//! meant to be reached from other machines - either behind a
//! TLS-terminating reverse proxy (Caddy/nginx), or with `serve
//! --tls-cert`/`--tls-key` for native TLS (see `tls.rs`), since
//! `kiln-image`'s client defaults to HTTPS for any host that isn't
//! `localhost`/`127.0.0.1`.

mod auth;
mod gc;
mod handlers;
mod server;
mod store;
mod tls;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use store::{RegistryStore, Role, User};

#[derive(Parser)]
#[command(name = "kiln-registry", version, about = "Kiln's self-hosted OCI Distribution registry")]
struct Cli {
    /// Where blobs, manifests, and the user database live (defaults to
    /// $KILN_REGISTRY_DATA, or ~/.kiln-registry)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the registry server (the default if no subcommand is given)
    Serve {
        /// TCP port to listen on (defaults to $KILN_REGISTRY_PORT, or 5959)
        #[arg(long)]
        port: Option<u16>,
        /// PEM certificate chain for native TLS (defaults to
        /// $KILN_REGISTRY_TLS_CERT). Requires --tls-key too; omit both
        /// for plain HTTP (the default - nothing changes unless this is
        /// explicitly set).
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// PEM private key matching --tls-cert (defaults to
        /// $KILN_REGISTRY_TLS_KEY).
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    /// Manage user accounts - there's no self-registration; a server
    /// admin provisions each account by hand
    User {
        #[command(subcommand)]
        cmd: UserCommand,
    },
    /// Delete blobs no longer referenced by any stored manifest - see
    /// `gc.rs`'s own docs on how this differs from `kiln gc` (the main
    /// runtime's local-store equivalent).
    Gc {
        /// Report what would be removed without deleting anything
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a new account, or reset an existing one's password. Only
    /// this user may push to repositories under `<username>/...` (unless
    /// `--role admin`, which can push anywhere). Omitting `--role` on an
    /// *existing* account leaves its current role untouched - this is
    /// "reset the password", not "reset the role" too.
    Add {
        username: String,
        password: String,
        /// `push` (default for a brand new account), `pull`, or `admin` -
        /// see `store::Role`'s own docs
        #[arg(long)]
        role: Option<Role>,
    },
    /// Change an existing account's role without touching its password.
    SetRole { username: String, role: Role },
}

fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KILN_REGISTRY_DATA") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".kiln-registry")
}

fn default_port() -> u16 {
    std::env::var("KILN_REGISTRY_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(5959)
}

fn default_tls_cert() -> Option<PathBuf> {
    std::env::var("KILN_REGISTRY_TLS_CERT").ok().map(PathBuf::from)
}

fn default_tls_key() -> Option<PathBuf> {
    std::env::var("KILN_REGISTRY_TLS_KEY").ok().map(PathBuf::from)
}

fn main() {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    let store = match RegistryStore::open(data_dir.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln-registry: opening data dir at {}: {e}", data_dir.display());
            std::process::exit(1);
        }
    };

    match cli.command {
        None => {
            if let Err(e) = server::run(store, default_port(), None) {
                eprintln!("kiln-registry: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Serve { port, tls_cert, tls_key }) => {
            let port = port.unwrap_or_else(default_port);
            let tls_cert = tls_cert.or_else(default_tls_cert);
            let tls_key = tls_key.or_else(default_tls_key);
            let tls = match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => Some((cert, key)),
                (None, None) => None,
                _ => {
                    eprintln!("kiln-registry: --tls-cert and --tls-key must both be given (or neither, for plain HTTP)");
                    std::process::exit(1);
                }
            };
            if let Err(e) = server::run(store, port, tls) {
                eprintln!("kiln-registry: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::User {
            cmd: UserCommand::Add { username, password, role },
        }) => {
            let mut users = store.load_users();
            let password_hash = auth::hash_password(&password);
            match users.iter_mut().find(|u| u.username == username) {
                Some(existing) => {
                    existing.password_hash = password_hash;
                    if let Some(role) = role {
                        existing.role = role;
                    }
                }
                None => users.push(User {
                    username: username.clone(),
                    password_hash,
                    public_key: None,
                    role: role.unwrap_or_default(),
                }),
            }
            if let Err(e) = store.save_users(&users) {
                eprintln!("kiln-registry: saving users: {e}");
                std::process::exit(1);
            }
            println!("{username}");
        }
        Some(Command::User {
            cmd: UserCommand::SetRole { username, role },
        }) => {
            if let Err(e) = store.set_role(&username, role) {
                eprintln!("kiln-registry: {e}");
                std::process::exit(1);
            }
            println!("{username}: role set to {role:?}");
        }
        Some(Command::Gc { dry_run }) => {
            let summary = gc::collect_garbage(&store, dry_run);
            let verb = if dry_run { "would remove" } else { "removed" };
            println!(
                "{verb} {} blob{} ({})",
                summary.blobs_removed,
                if summary.blobs_removed == 1 { "" } else { "s" },
                format_bytes(summary.bytes_freed),
            );
        }
    }
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}
