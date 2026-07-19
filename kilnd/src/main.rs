//! `kilnd`: an *optional* daemon exposing the same runtime `kiln` drives
//! directly, over a local HTTP API served on a Unix socket - for
//! shared/CI hosts where a persistent process is acceptable, and as the
//! backend `kiln-dashboard` (an Electron app) talks to. Kiln's default
//! remains daemonless direct mode; nothing about `kiln`/`kiln-compose`
//! requires `kilnd` to be running, and starting it doesn't change how
//! containers are created (it calls the exact same
//! `kiln_cli::commands::run::start` every direct CLI invocation does).

mod handlers;
mod server;

use clap::Parser;
use kiln_image::store::Store;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kilnd", version, about = "Kiln's optional local HTTP API daemon")]
struct Cli {
    /// Path to the Kiln store (defaults to $KILN_STORE, or ~/.kiln)
    #[arg(long)]
    store: Option<PathBuf>,

    /// Unix socket to listen on (defaults to <store>/kilnd.sock)
    #[arg(long)]
    socket: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let store_root = cli.store.unwrap_or_else(kiln_cli::default_store);

    let store = match Store::open(&store_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kilnd: opening store at {}: {e}", store_root.display());
            std::process::exit(1);
        }
    };

    let socket_path = cli.socket.unwrap_or_else(|| store_root.join("kilnd.sock"));

    if let Err(e) = server::run(store, &socket_path) {
        eprintln!("kilnd: {e}");
        std::process::exit(1);
    }
}
