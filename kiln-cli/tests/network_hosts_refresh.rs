//! Real reproduction of the bug found live on a user's own `kiln-compose`
//! stack: a container that restarts individually (not via a fresh
//! `kiln-compose up`) gets a brand new IP (`NetworkConfig::allocate_ip`
//! never reuses one), but every *other* container already on the network
//! kept whatever `/etc/hosts` it was given at its own creation time -
//! stale forever, since nothing ever rewrote it afterward.
//!
//! `commands::network::refresh_network_hosts` (called from
//! `supervisor.rs` every time a container's IP is (re)assigned) is what
//! closes that gap. This test doesn't go through `kiln-compose` at all -
//! it uses two plain `kiln run`-style containers on an ordinary network,
//! to prove the fix isn't compose-specific (the same fix helps any
//! container sharing a network, per the report).
//!
//! Needs outbound network access to pull `busybox:latest`; skips (rather
//! than failing the suite) if Docker Hub isn't reachable, matching
//! `kiln-image/tests/registry_pull.rs`.

use kiln_cli::commands::{network, run, stop};
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::time::Duration;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container/network requires root in this environment");
        return false;
    }
    true
}

fn read_hosts(store: &Store, container_id: &str) -> String {
    std::fs::read_to_string(kiln_cli::container::Container::upper_dir(store, container_id).join("etc/hosts")).unwrap_or_default()
}

#[test]
fn a_sibling_restarted_individually_gets_its_new_ip_propagated() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    network::run(
        &store,
        network::Command::Create {
            name: "hostsrefreshtest".to_string(),
            subnet: "172.31.0.0/24".to_string(),
        },
    )
    .expect("create network");

    let mut spec_a = run::RunSpec::new("busybox:latest");
    spec_a.name = Some("a".to_string());
    spec_a.command = vec!["/bin/sh".to_string(), "-c".to_string(), "sleep 300".to_string()];
    spec_a.network = Some("hostsrefreshtest".to_string());
    let container_a = run::start(&store, spec_a, None).expect("start a");
    let ip_a_before = container_a.ip.clone().expect("a should have an ip");

    let mut spec_b = run::RunSpec::new("busybox:latest");
    spec_b.name = Some("b".to_string());
    spec_b.command = vec!["/bin/sh".to_string(), "-c".to_string(), "sleep 300".to_string()];
    spec_b.network = Some("hostsrefreshtest".to_string());
    let container_b = run::start(&store, spec_b, None).expect("start b");

    // Give both supervisors a moment to persist state before reading it back.
    std::thread::sleep(Duration::from_millis(300));

    let hosts_b_before = read_hosts(&store, &container_b.id);
    assert!(
        hosts_b_before.contains(&format!("{ip_a_before}\ta")),
        "b should already resolve a's original ip right after both started: {hosts_b_before:?}"
    );

    // Restart `a` alone - not through any compose group, just like the
    // real-world report - forcing a fresh IP allocation.
    stop::stop_container(&store, &container_a.id).expect("stop a");
    std::thread::sleep(Duration::from_millis(300));
    let restarted_a = run::restart(&store, "a").expect("restart a");
    let ip_a_after = restarted_a.ip.clone().expect("restarted a should have a new ip");
    assert_ne!(
        ip_a_before, ip_a_after,
        "a real restart should allocate a fresh ip, not reuse the old one"
    );

    std::thread::sleep(Duration::from_millis(300));

    let hosts_b_after = read_hosts(&store, &container_b.id);

    let _ = stop::stop_container(&store, &restarted_a.id);
    let _ = stop::stop_container(&store, &container_b.id);
    kiln_cli::cgroup::remove(&restarted_a.id);
    kiln_cli::cgroup::remove(&container_b.id);
    let _ = network::run(
        &store,
        network::Command::Rm {
            name: "hostsrefreshtest".to_string(),
        },
    );

    assert!(
        !hosts_b_after.contains(&format!("{ip_a_before}\ta")),
        "b's /etc/hosts should no longer hold a's stale, pre-restart ip: {hosts_b_after:?}"
    );
    assert!(
        hosts_b_after.contains(&format!("{ip_a_after}\ta")),
        "b's /etc/hosts should have been refreshed with a's new ip after a's individual restart, with no manual intervention: {hosts_b_after:?}"
    );
}
