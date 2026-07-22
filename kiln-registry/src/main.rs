//! `kiln-registry`: a self-hosted OCI Distribution registry server, so
//! one Kiln user can `kiln push` an image and another can `kiln pull`
//! the same reference (`<host>/<username>/<image>:<tag>`) - no
//! third-party registry account needed. See the module docs on
//! `handlers` for exactly which slice of the OCI Distribution API is
//! implemented.
//!
//! Unlike `kilnd` (loopback-only, a local dashboard backend), this is
//! meant to be reached from other machines - run it behind a
//! TLS-terminating reverse proxy (Caddy/nginx) for anything beyond a
//! trusted LAN, since `kiln-image`'s client defaults to HTTPS for any
//! host that isn't `localhost`/`127.0.0.1`.

mod auth;
mod handlers;
mod server;
mod store;

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
    },
    /// Manage user accounts - there's no self-registration; a server
    /// admin provisions each account by hand
    User {
        #[command(subcommand)]
        cmd: UserCommand,
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
        None | Some(Command::Serve { .. }) => {
            let port = match cli.command {
                Some(Command::Serve { port: Some(p) }) => p,
                _ => default_port(),
            };
            if let Err(e) = server::run(store, port) {
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
    }
}
