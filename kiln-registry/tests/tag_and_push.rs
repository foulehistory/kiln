//! Real end-to-end proof that `kiln tag` (`kiln_image::image::tag_reference`)
//! is the missing step that makes pushing an image under a name other
//! than its own local tag actually work: `kiln_image::registry::push` (and
//! `Image::resolve` underneath it) only ever pushes whatever a reference
//! already resolves to *locally* - it never renames on the fly, the same
//! way `docker push registry.example.com/you/app:latest` needs a `docker
//! tag` first. Builds a tiny local image, tags it under an explicit-host
//! reference this (freshly started, empty) registry has never seen,
//! pushes it there, then pulls it back under that exact name and confirms
//! it's the same content - the exact round trip the dashboard's "Push to
//! shared registry" button relies on.

use kiln_image::build;
use kiln_image::image::{tag_reference, Image};
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: building/materializing requires root in this environment");
        return false;
    }
    true
}

struct Registry {
    child: Child,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_registry(data_dir: &Path, port: u16) -> Registry {
    let child = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args(["--data-dir", data_dir.to_str().unwrap(), "serve", "--port", &port.to_string()])
        .spawn()
        .expect("spawn kiln-registry");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Registry { child };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("kiln-registry never started listening on 127.0.0.1:{port}");
}

fn add_user(data_dir: &Path, username: &str, password: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_kiln-registry"))
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "user",
            "add",
            username,
            password,
            "--role",
            "admin",
        ])
        .status()
        .expect("run kiln-registry user add");
    assert!(status.success());
}

#[test]
fn tag_then_push_to_explicit_host_round_trips() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let ctx = tempfile::tempdir().unwrap();
    std::fs::write(ctx.path().join("hello.txt"), "hello from tag_and_push\n").unwrap();

    let kilnfile = "\
FROM scratch
COPY hello.txt /hello.txt
";
    let output = build::build(&store, ctx.path(), kilnfile).expect("build");
    let image = Image::load(&store, &output.image_id).expect("load built image");
    assert_eq!(image.layers.len(), 1);

    // Confirm the actual bug this is guarding against: `kiln push`/kilnd's
    // push handler both resolve the *target* reference locally before
    // ever calling `registry::push` (see their own source) - so an
    // explicit-host name that was never tagged locally fails right there,
    // with nothing implicitly renaming it into existence.
    let untagged_reference = "127.0.0.1:0/nobody/never-tagged:latest";
    Image::resolve(&store, untagged_reference).expect_err("an explicit-host name nothing tagged yet must not resolve");

    let registry_dir = tempfile::tempdir().unwrap();
    let port = 15900 + (std::process::id() % 500) as u16;
    add_user(registry_dir.path(), "alice", "hunter2");
    let _registry = spawn_registry(registry_dir.path(), port);

    let target = format!("127.0.0.1:{port}/alice/hello:latest");
    tag_reference(&store, &output.image_id, &target).expect("tag under the explicit-host name");

    // Now it resolves - the exact fix: same reference, only difference is
    // the `tag_reference` call above.
    let resolved = Image::resolve(&store, &target).expect("resolves now that it's tagged").id();
    assert_eq!(resolved, output.image_id);

    std::env::set_var("KILN_REGISTRY_USER", "alice");
    std::env::set_var("KILN_REGISTRY_PASS", "hunter2");
    registry::push(&store, &output.image_id, &target).expect("push the freshly-tagged reference");

    // Pull it back into a *different*, empty store to prove the content
    // really made it to the registry, not just that the local tag exists.
    let pull_store_dir = tempfile::tempdir().unwrap();
    let pull_store = Store::open(pull_store_dir.path()).unwrap();
    let pulled_id = registry::pull(&pull_store, &target, true).expect("pull back from the registry");
    let pulled = Image::load(&pull_store, &pulled_id).expect("load pulled image");
    assert_eq!(pulled.layers.len(), image.layers.len());

    let dir = kiln_image::layer::materialize_cached(
        &pull_store,
        pulled.layers.last().unwrap(),
        kiln_image::identity::SUBORDINATE_UID_BASE,
        kiln_image::identity::SUBORDINATE_GID_BASE,
    )
    .unwrap();
    let content = std::fs::read_to_string(dir.join("hello.txt")).expect("hello.txt round-tripped through the registry");
    assert_eq!(content, "hello from tag_and_push\n");
}
