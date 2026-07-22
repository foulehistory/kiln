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
        "{:<14}{:<20}{:<12}{:<11}{:<10}{:<20}COMMAND",
        "CONTAINER ID", "IMAGE", "STATUS", "HEALTH", "PID", "NAME"
    );
    for c in &containers {
        let status = match c.status {
            Status::Running => "running".to_string(),
            Status::Exited(code) => format!("exited({code})"),
        };
        let health = if c.healthcheck.is_some() { c.health.as_str() } else { "-" };
        let pid = c.pid.map(|p| p.to_string()).unwrap_or_default();
        let cmd = c.command.join(" ");
        println!(
            "{:<14}{:<20}{:<12}{:<11}{:<10}{:<20}{}",
            &c.id[..12.min(c.id.len())],
            truncate(&c.image_reference, 18),
            status,
            health,
            pid,
            truncate(&c.name, 18),
            truncate(&cmd, 40),
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max.saturating_sub(1)])
    } else {
        s.to_string()
    }
}
