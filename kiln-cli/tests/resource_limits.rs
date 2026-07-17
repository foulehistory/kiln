//! `--memory`/`--cpus`: the size parser, and that the resulting cgroup
//! actually reflects the requested limits - both on first `run` and after
//! a `start` (restart), since those limits are persisted specifically so
//! a restart doesn't silently revert to unlimited.

use kiln_cli::commands::run::{parse_size, start, RunSpec};
use kiln_image::store::Store;
use nix::unistd::Uid;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real cgroup/container requires root in this environment");
        return false;
    }
    true
}

#[test]
fn parse_size_accepts_docker_style_suffixes() {
    assert_eq!(parse_size("512"), Ok(512));
    assert_eq!(parse_size("512k"), Ok(512 * 1024));
    assert_eq!(parse_size("32m"), Ok(32 * 1024 * 1024));
    assert_eq!(parse_size("1g"), Ok(1024 * 1024 * 1024));
    assert_eq!(parse_size("1G"), Ok(1024 * 1024 * 1024));
    assert!(parse_size("not-a-size").is_err());
}

#[test]
fn memory_and_cpu_limits_apply_to_the_real_cgroup_and_survive_a_restart() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let mut spec = RunSpec::new("scratch");
    spec.command = vec!["/nonexistent".to_string()];
    spec.memory_limit_bytes = Some(64 * 1024 * 1024);
    spec.cpu_limit = Some(0.25);

    // The command itself is bound to fail (no such binary in an empty
    // rootfs) - irrelevant here, since the cgroup is created and limits
    // applied before the container's command ever runs.
    let container = start(&store, spec, None).expect("start");

    let cgroup_dir = format!("/sys/fs/cgroup/kiln/{}", container.id);
    let mem_max: u64 = std::fs::read_to_string(format!("{cgroup_dir}/memory.max")).unwrap().trim().parse().unwrap();
    assert_eq!(mem_max, 64 * 1024 * 1024);
    let cpu_max = std::fs::read_to_string(format!("{cgroup_dir}/cpu.max")).unwrap();
    assert_eq!(cpu_max.trim(), "25000 100000");

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    let restarted = kiln_cli::commands::run::restart(&store, &container.id).expect("restart");
    assert_eq!(restarted.id, container.id, "restart reuses the same container id");

    let cgroup_dir = format!("/sys/fs/cgroup/kiln/{}", restarted.id);
    let mem_max: u64 = std::fs::read_to_string(format!("{cgroup_dir}/memory.max")).unwrap().trim().parse().unwrap();
    assert_eq!(mem_max, 64 * 1024 * 1024, "restart should reapply the same memory limit");
    let cpu_max = std::fs::read_to_string(format!("{cgroup_dir}/cpu.max")).unwrap();
    assert_eq!(cpu_max.trim(), "25000 100000", "restart should reapply the same cpu limit");

    let _ = kiln_cli::commands::stop::stop_container(&store, &restarted.id);
    kiln_cli::cgroup::remove(&restarted.id);
}
