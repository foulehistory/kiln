//! `kiln`: the Kiln container CLI. Daemonless by default - every command
//! here does its own `clone(2)`/mount/cgroup work directly via
//! `kilnd-core`, with no persistent background service required (the one
//! partial exception, `kiln run -d`'s per-container supervisor, is
//! explained in `kiln_cli::supervisor`).

use clap::{Parser, Subcommand};
use kiln_cli::commands;
use kiln_image::store::Store;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kiln", version, about = "A daemonless, rootless-by-default container runtime")]
struct Cli {
    /// Path to the Kiln store (defaults to $KILN_STORE, or ~/.kiln)
    #[arg(long, global = true)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command in a new container
    Run(commands::run::Args),
    /// Restart a stopped container, reusing its existing writable state
    Start(commands::start::Args),
    /// Stop one or more running containers (SIGTERM, then SIGKILL if needed)
    Stop(commands::stop::Args),
    /// Build an image from a Kilnfile
    Build(commands::build::Args),
    /// Pull an image from a registry
    Pull(commands::pull::Args),
    /// Push an image to a registry
    Push(commands::push::Args),
    /// List containers
    Ps(commands::ps::Args),
    /// List local images
    Images(commands::images::Args),
    /// Run a command in a running container
    Exec(commands::exec::Args),
    /// Fetch a container's logs
    Logs(commands::logs::Args),
    /// Remove one or more containers
    Rm(commands::rm::Args),
    /// Remove (untag) one or more images
    Rmi(commands::rmi::Args),
    /// Reclaim disk space: delete blobs/images no longer referenced by any tag
    Gc(commands::gc::Args),
    /// Manage volumes
    #[command(subcommand)]
    Volume(commands::volume::Command),
    /// Manage networks
    #[command(subcommand)]
    Network(commands::network::Command),
}

fn main() {
    let cli = Cli::parse();
    let store_root = cli.store.unwrap_or_else(kiln_cli::default_store);

    let store = match Store::open(&store_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("kiln: failed to open store at {}: {e}", store_root.display());
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Command::Run(args) => commands::run::run(&store, args),
        Command::Start(args) => commands::start::run(&store, args),
        Command::Stop(args) => commands::stop::run(&store, args),
        Command::Build(args) => commands::build::run(&store, args),
        Command::Pull(args) => commands::pull::run(&store, args),
        Command::Push(args) => commands::push::run(&store, args),
        Command::Ps(args) => commands::ps::run(&store, args),
        Command::Images(args) => commands::images::run(&store, args),
        Command::Exec(args) => commands::exec::run(&store, args),
        Command::Logs(args) => commands::logs::run(&store, args),
        Command::Rm(args) => commands::rm::run(&store, args),
        Command::Rmi(args) => commands::rmi::run(&store, args),
        Command::Gc(args) => commands::gc::run(&store, args),
        Command::Volume(cmd) => commands::volume::run(&store, cmd),
        Command::Network(cmd) => commands::network::run(&store, cmd),
    };

    if let Err(e) = result {
        eprintln!("kiln: {e}");
        std::process::exit(1);
    }
}
