use crate::container::{Container, Status};
use crate::error::CliResult;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    pub containers: Vec<String>,

    /// Kill the container first if it's still running
    #[arg(short = 'f', long)]
    pub force: bool,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    for name in &args.containers {
        let mut container = match Container::resolve(store, name) {
            Some(c) => c,
            None => {
                eprintln!("kiln: no such container: {name}");
                continue;
            }
        };
        container.refresh(store);

        if container.status == Status::Running {
            if !args.force {
                eprintln!("kiln: container {} is running (use -f to force)", container.id);
                continue;
            }
            if let Some(pid) = container.pid {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
            // The cgroup can't be removed until the kernel has finished
            // reaping the killed process out of it; a few short retries
            // covers the normal case without making `rm -f` feel slow.
            for _ in 0..10 {
                let empty = crate::cgroup::open(&container.id)
                    .and_then(|dir| std::fs::read_to_string(dir.join("cgroup.procs")).ok())
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true);
                if empty {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        crate::cgroup::remove(&container.id);

        let dir = Container::dir(store, &container.id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => println!("{}", container.id),
            Err(e) => eprintln!("kiln: removing {}: {e}", dir.display()),
        }
    }
    Ok(())
}
