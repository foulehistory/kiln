//! `kiln top` - live resource usage for one or all running containers, in
//! the CLI. The underlying stats (`kiln_cli::cgroup::stats`) already
//! existed purely for `kilnd`'s dashboard API; this is just a text
//! front-end for the same numbers when there's no dashboard running.

use crate::container::{Container, Status};
use crate::error::CliResult;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Show only this container (defaults to every running one)
    pub container: Option<String>,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let containers: Vec<Container> = match &args.container {
        Some(name) => Container::resolve(store, name).into_iter().collect(),
        None => {
            let mut all = Container::list(store);
            for c in &mut all {
                c.refresh(store);
            }
            all.into_iter().filter(|c| c.status == Status::Running).collect()
        }
    };

    println!("{:<14}{:<20}{:<10}{:<12}PIDS", "CONTAINER ID", "NAME", "CPU (ms)", "MEMORY");
    for c in &containers {
        let Some(stats) = crate::cgroup::stats(&c.id) else { continue };
        println!(
            "{:<14}{:<20}{:<10}{:<12}{}",
            &c.id[..12.min(c.id.len())],
            &c.name[..c.name.len().min(19)],
            stats.cpu_usage_usec / 1000,
            format_bytes(stats.memory_current_bytes),
            stats.pids_current,
        );
    }
    Ok(())
}

fn format_bytes(n: u64) -> String {
    if n < 1024 * 1024 {
        format!("{:.0} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    }
}
