//! `kiln doctor` - find (and, with `--fix`, clean up) orphaned cgroup
//! member processes: leftovers from a `start` attempt that was itself
//! interrupted (kilnd/kiln killed mid-launch, e.g. a host/VM restart)
//! before the container's process either exited on its own or went
//! through `stop`'s own reaping. `CgroupV2::create` already self-heals
//! this automatically the next time the *same* container id tries to
//! start (see its own docs on the `EBUSY` it used to surface instead) -
//! this command is for finding and fixing it proactively, across every
//! container, without needing to hit that error first.

use crate::container::{Container, Status};
use crate::error::CliResult;
use kiln_image::store::Store;
use kilnd_core::cgroups::{reap_orphaned_members, CgroupV2};
use std::path::Path;
use std::time::{Duration, SystemTime};

const MOUNT_ROOT: &str = "/sys/fs/cgroup";

/// A cgroup directory must be at least this old before `doctor` will
/// consider its members orphaned.
///
/// `CgroupV2::create` for a *new* start runs well before that container's
/// own `Running` status is persisted (see `commands::run::start`'s own
/// ordering: cgroup first, then namespaces/spawn, then network attach,
/// then finally `container.save`). A system-wide sweep with no grace
/// period would have a real window to race a container that's still
/// legitimately mid-start elsewhere (a different id, e.g. a second `kiln
/// run` or the dashboard launching something), flagging - and with
/// `--fix`, killing - a perfectly healthy in-flight container. A few
/// seconds is already far longer than kiln's own spawn path normally
/// takes end to end.
const MIN_AGE_BEFORE_FLAGGING: Duration = Duration::from_secs(3);

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Actually kill orphaned processes (and remove their cgroup, if the
    /// container itself no longer exists) instead of just reporting them.
    #[arg(long)]
    pub fix: bool,
}

struct Finding {
    container_id: String,
    /// `None` when the container this cgroup was created for has since
    /// been fully removed from the store - the cgroup directory itself is
    /// the only trace left of it.
    container_name: Option<String>,
    pids: Vec<i32>,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let cgroup_root = Path::new(MOUNT_ROOT).join("kiln");
    let Ok(entries) = std::fs::read_dir(&cgroup_root) else {
        println!("no cgroups under {} - nothing to check", cgroup_root.display());
        return Ok(());
    };

    let containers = Container::list(store);
    let mut findings = Vec::new();

    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let Some(id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let container = containers.iter().find(|c| c.id == id);
        // A *running* container is expected to have member processes -
        // that's not orphaned, that's the container doing its job.
        if container.is_some_and(|c| c.status == Status::Running) {
            continue;
        }
        // See `MIN_AGE_BEFORE_FLAGGING`'s own docs: skip anything young
        // enough to still just be a normal, in-progress start elsewhere.
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok());
        match age {
            Some(age) if age >= MIN_AGE_BEFORE_FLAGGING => {}
            _ => continue,
        }
        let pids = CgroupV2::from_existing(entry.path()).processes().unwrap_or_default();
        if pids.is_empty() {
            continue;
        }
        findings.push(Finding {
            container_id: id,
            container_name: container.map(|c| c.name.clone()),
            pids: pids.into_iter().map(|p| p.as_raw()).collect(),
        });
    }

    if findings.is_empty() {
        println!("no orphaned cgroup processes found");
        return Ok(());
    }

    for f in &findings {
        let label = f.container_name.as_deref().unwrap_or("(container no longer exists)");
        println!(
            "{}  {}  {} orphaned process(es): {:?}",
            &f.container_id[..12.min(f.container_id.len())],
            label,
            f.pids.len(),
            f.pids
        );
    }

    if !args.fix {
        println!("run `kiln doctor --fix` to kill these and clear the way for a future start/restart");
        return Ok(());
    }

    for f in &findings {
        let dir = cgroup_root.join(&f.container_id);
        let killed = reap_orphaned_members(&dir);
        println!("{}: killed {} process(es)", &f.container_id[..12.min(f.container_id.len())], killed.len());
        if f.container_name.is_none() {
            // Nothing will ever restart under this id again - the cgroup
            // itself (not just its members) is pure leftover.
            let _ = std::fs::remove_dir(&dir);
        }
    }

    Ok(())
}
