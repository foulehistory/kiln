//! `kiln cp`: a host->container write followed by a container->host read
//! should round-trip the same bytes. Writing through `/proc/<pid>/root`
//! directly doesn't work in this project's WSL2/overlayfs environment
//! (`EOVERFLOW` on create, confirmed with plain `cp` too - not a bug in
//! this code) - `write_into_container` instead joins the container's
//! `user`+`mnt` namespaces and writes through its actual live mount. This
//! test is what caught the original bug and would catch a regression back
//! to the naive approach.
//!
//! Needs outbound network access to pull `busybox:latest`; skips (rather
//! than failing the suite) if Docker Hub isn't reachable, matching
//! `kiln-image/tests/registry_pull.rs`.

use kiln_cli::commands::{cp, run};
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: creating a real container requires root in this environment");
        return false;
    }
    true
}

#[test]
fn host_to_container_and_back_round_trips_file_content() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    if let Err(e) = registry::pull(&store, "busybox:latest", false) {
        eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
        return;
    }

    let mut spec = run::RunSpec::new("busybox:latest");
    spec.command = vec!["/bin/sh".to_string(), "-c".to_string(), "sleep 60".to_string()];
    let container = run::start(&store, spec, None).expect("start");

    let ctx = tempfile::tempdir().unwrap();
    let host_src = ctx.path().join("source.txt");
    let host_dst = ctx.path().join("roundtrip.txt");
    std::fs::write(&host_src, "cp-round-trip-content\n").unwrap();

    let into_result = cp::run(
        &store,
        cp::Args { src: host_src.to_str().unwrap().to_string(), dst: format!("{}:/tmp/copied.txt", container.name) },
    );
    let out_result = cp::run(
        &store,
        cp::Args { src: format!("{}:/tmp/copied.txt", container.name), dst: host_dst.to_str().unwrap().to_string() },
    );

    let _ = kiln_cli::commands::stop::stop_container(&store, &container.id);
    kiln_cli::cgroup::remove(&container.id);

    into_result.expect("copying into the container should succeed");
    out_result.expect("copying back out of the container should succeed");
    let roundtripped = std::fs::read_to_string(&host_dst).expect("roundtrip.txt should have been written");
    assert_eq!(roundtripped, "cp-round-trip-content\n");
}
