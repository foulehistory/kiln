use crate::container::{Container, Status};
use crate::error::CliResult;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Show all containers, not just running ones
    #[arg(short = 'a', long)]
    pub all: bool,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let mut containers = Container::list(store);
    for c in &mut containers {
        c.refresh(store);
    }
    if !args.all {
        containers.retain(|c| c.status == Status::Running);
    }

    println!(
        "{:<14}{:<20}{:<12}{:<11}{:<10}{:<20}{:<10}{:<12}COMMAND",
        "CONTAINER ID", "IMAGE", "STATUS", "HEALTH", "PID", "NAME", "CPU(ms)", "MEM"
    );
    for c in &containers {
        let status = match c.status {
            Status::Running => "running".to_string(),
            Status::Exited(code) => format!("exited({code})"),
        };
        let health = if c.healthcheck.is_some() { c.health.as_str() } else { "-" };
        let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
        let cmd = c.command.join(" ");
        // Cumulative CPU time (not a live percentage - see
        // `crate::cgroup::Stats::cpu_usage_usec`'s own docs) and current
        // memory, both "-" when the container has no cgroup (never
        // started, or removed).
        let stats = crate::cgroup::stats(&c.id);
        let cpu = stats
            .as_ref()
            .map(|s| (s.cpu_usage_usec / 1000).to_string())
            .unwrap_or_else(|| "-".to_string());
        let mem = stats
            .as_ref()
            .map(|s| format_bytes(s.memory_current_bytes))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<14}{:<20}{:<12}{:<11}{:<10}{:<20}{:<10}{:<12}{}",
            &c.id[..12.min(c.id.len())],
            truncate(&c.image_reference, 18),
            status,
            health,
            pid,
            truncate(&c.name, 18),
            cpu,
            mem,
            truncate(&cmd, 40),
        );
    }
    Ok(())
}

/// Human-readable byte size for the MEM column, e.g. `12.3MiB` - not
/// reused elsewhere, so kept local rather than a shared utility.
fn format_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut value = b as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max.saturating_sub(1)])
    } else {
        s.to_string()
    }
}
