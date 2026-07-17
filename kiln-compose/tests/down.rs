//! `kiln-compose down` must tear down the `<project>_default` bridge
//! network `up` creates, not just the containers - it used to leave the
//! bridge (and its iptables MASQUERADE rule) behind entirely, the same
//! class of orphan that needed manual `ip link del` cleanup during
//! development. `kiln-compose` has no library target (only `main.rs`), so
//! this drives the real compiled binary as a subprocess rather than
//! calling `cmd_up`/`cmd_down` directly.

use kiln_cli::commands::network::NetworkConfig;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::process::Command;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating bridges/iptables rules requires root in this environment");
        return false;
    }
    true
}

fn bridge_exists(bridge: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", bridge])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn down_removes_the_project_network_it_created() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let project_dir = tempfile::tempdir().unwrap();
    // `image: scratch` never actually starts (no /bin/sh in an empty
    // rootfs) - irrelevant here, since `up` creates the project's network
    // *before* attempting to start any service.
    std::fs::write(
        project_dir.path().join("kiln.yaml"),
        "services:\n  svc:\n    image: scratch\n    command: [\"/bin/sh\"]\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_kiln-compose");
    let run = |args: &[&str]| {
        Command::new(bin)
            .args(["--store", store_dir.path().to_str().unwrap(), "-f", "kiln.yaml", "-p", "downtest"])
            .args(args)
            .current_dir(project_dir.path())
            .output()
            .expect("spawn kiln-compose")
    };

    run(&["up", "-d"]);

    let network = NetworkConfig::load(&store, "downtest_default").expect("up should have created the project network");
    let bridge = network.bridge.clone();
    assert!(bridge_exists(&bridge), "sanity check: the bridge should exist right after `up`");

    let down_output = run(&["down"]);
    assert!(down_output.status.success(), "down failed: {}", String::from_utf8_lossy(&down_output.stderr));

    assert!(NetworkConfig::load(&store, "downtest_default").is_none(), "down should remove the network's stored config");
    assert!(!bridge_exists(&bridge), "down should remove the bridge device itself, not just the config file");
}
