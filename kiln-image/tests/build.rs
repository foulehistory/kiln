//! End-to-end tests for the Kilnfile build engine: real containers are
//! spawned via kilnd-core to run `RUN` steps, real overlayfs diffs are
//! captured as layers, and the resulting images are materialized and
//! inspected from the host side to confirm they actually contain what the
//! Kilnfile said they should.
//!
//! `FROM scratch` starts with a genuinely empty filesystem - no shell, no
//! nothing - so any test that wants to exercise `RUN` needs to `COPY` one
//! in first. We use the host's own `busybox` (statically linked, so it
//! has no dynamic-linker/shared-library dependencies to also copy in) as
//! `/bin/sh`, which is enough to run the plain shell one-liners these
//! tests use.

use kiln_image::build;
use kiln_image::image::Image;
use kiln_image::layer;
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::fs;
use std::path::Path;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: build steps spawn real containers, which needs root in this environment");
        return false;
    }
    true
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

/// Copy a statically-linked shell into the build context as `busybox`, for
/// Kilnfiles to `COPY busybox /bin/sh` before any `RUN`. Skips the test
/// (rather than failing it) if no static busybox is installed.
fn stage_busybox(ctx: &Path) -> bool {
    for candidate in ["/usr/bin/busybox", "/bin/busybox"] {
        let src = Path::new(candidate);
        if src.is_file() {
            let dest = ctx.join("busybox");
            fs::copy(src, &dest).expect("copy busybox into build context");
            return true;
        }
    }
    eprintln!("skipping: no static busybox found (apt-get install busybox-static) to act as a shell for RUN steps");
    false
}

#[test]
fn from_scratch_run_and_copy_produce_expected_files() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let ctx = tempfile::tempdir().unwrap();
    if !stage_busybox(ctx.path()) {
        return;
    }
    write(&ctx.path().join("app/hello.txt"), "hello from the build context\n");

    let kilnfile = "\
FROM scratch
COPY busybox /bin/sh
RUN mkdir -p /out && echo made-by-run > /out/run.txt
COPY app/hello.txt /app/hello.txt
ENV GREETING=hi
WORKDIR /app
CMD cat hello.txt
";

    let output = build::build(&store, ctx.path(), kilnfile).expect("build");
    assert_eq!(output.steps.len(), 6, "COPY, RUN, COPY, ENV, WORKDIR, CMD");
    assert!(output.steps.iter().all(|s| !s.cached), "first build: nothing should be cached");

    let image = Image::load(&store, &output.image_id).expect("load built image");
    assert_eq!(image.config.env_get("GREETING"), Some("hi"));
    assert_eq!(image.config.workdir, "/app");
    assert_eq!(image.config.cmd.as_deref(), Some("cat hello.txt"));
    // scratch contributes no layers; the two COPYs and the RUN each add one.
    assert_eq!(image.layers.len(), 3);

    // Materialize every layer and check its actual file content, the same
    // way `kilnd-core::rootfs` would assemble a real container's lowerdir
    // stack (each layer here touches disjoint paths, so just checking
    // each materialized layer independently is sufficient).
    for (i, id) in image.lower_dirs_order().enumerate() {
        let dir = layer::materialize_cached(
            &store,
            id,
            kiln_image::identity::SUBORDINATE_UID_BASE,
            kiln_image::identity::SUBORDINATE_GID_BASE,
        )
        .unwrap_or_else(|e| panic!("materialize layer {i}: {e}"));
        let run_txt = dir.join("out/run.txt");
        let hello_txt = dir.join("app/hello.txt");
        if run_txt.is_file() {
            assert_eq!(fs::read_to_string(run_txt).unwrap().trim(), "made-by-run");
        }
        if hello_txt.is_file() {
            assert_eq!(fs::read_to_string(hello_txt).unwrap(), "hello from the build context\n");
        }
    }
}

#[test]
fn unchanged_steps_are_served_from_cache() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let ctx = tempfile::tempdir().unwrap();
    if !stage_busybox(ctx.path()) {
        return;
    }

    let kilnfile_v1 = "\
FROM scratch
COPY busybox /bin/sh
RUN echo one > /one.txt
RUN echo two > /two.txt
";
    let out1 = build::build(&store, ctx.path(), kilnfile_v1).expect("first build");
    assert!(out1.steps.iter().all(|s| !s.cached));

    // Same Kilnfile again: every step should now hit the cache.
    let out2 = build::build(&store, ctx.path(), kilnfile_v1).expect("rebuild, unchanged");
    assert!(out2.steps.iter().all(|s| s.cached), "identical rebuild should be fully cached");
    assert_eq!(out1.image_id, out2.image_id);

    // Append a third RUN step: everything before it must stay cached, only
    // the new one should actually execute.
    let kilnfile_v2 = "\
FROM scratch
COPY busybox /bin/sh
RUN echo one > /one.txt
RUN echo two > /two.txt
RUN echo three > /three.txt
";
    let out3 = build::build(&store, ctx.path(), kilnfile_v2).expect("build with appended step");
    assert_eq!(out3.steps.len(), 4);
    assert!(out3.steps[0].cached, "unchanged COPY busybox should be cached");
    assert!(out3.steps[1].cached, "unchanged RUN one should be cached");
    assert!(out3.steps[2].cached, "unchanged RUN two should be cached");
    assert!(!out3.steps[3].cached, "new RUN three should actually run");
}

#[test]
fn changing_a_copy_source_invalidates_only_that_step_onward() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let ctx = tempfile::tempdir().unwrap();
    if !stage_busybox(ctx.path()) {
        return;
    }
    write(&ctx.path().join("unrelated.txt"), "never copied, should not affect caching\n");
    write(&ctx.path().join("data.txt"), "version 1\n");

    let kilnfile = "\
FROM scratch
COPY busybox /bin/sh
RUN echo base > /base.txt
COPY data.txt /data.txt
RUN echo after-copy > /after.txt
";

    let out1 = build::build(&store, ctx.path(), kilnfile).expect("first build");
    assert!(out1.steps.iter().all(|s| !s.cached));

    // Touching an unrelated context file must NOT invalidate anything.
    write(&ctx.path().join("unrelated.txt"), "changed, but COPY never referenced this file\n");
    let out2 = build::build(&store, ctx.path(), kilnfile).expect("rebuild after unrelated change");
    assert!(out2.steps.iter().all(|s| s.cached), "unrelated context change must not bust the cache");

    // Changing the actually-copied file must invalidate that COPY and
    // everything after it, but not the steps before it.
    write(&ctx.path().join("data.txt"), "version 2\n");
    let out3 = build::build(&store, ctx.path(), kilnfile).expect("rebuild after data.txt change");
    assert!(out3.steps[0].cached, "COPY busybox should remain cached");
    assert!(out3.steps[1].cached, "RUN before the changed COPY should remain cached");
    assert!(!out3.steps[2].cached, "COPY of the changed file must re-run");
    assert!(!out3.steps[3].cached, "RUN after the changed COPY must re-run too");
    assert_ne!(out1.image_id, out3.image_id);
}

#[test]
fn identical_build_on_two_independent_stores_produces_the_same_image_id() {
    if !require_root() {
        return;
    }

    let ctx = tempfile::tempdir().unwrap();
    if !stage_busybox(ctx.path()) {
        return;
    }
    write(&ctx.path().join("payload.txt"), "reproducibility check\n");
    let kilnfile = "\
FROM scratch
COPY busybox /bin/sh
RUN mkdir -p /a/b/c && echo x > /a/b/c/f.txt
COPY payload.txt /payload.txt
ENV X=1
";

    // Two completely separate stores (as if on two different machines): a
    // cache hit on one cannot leak into the other, so this genuinely
    // exercises reproducibility, not just cache replay.
    let store_a = Store::open(tempfile::tempdir().unwrap().keep()).unwrap();
    let store_b = Store::open(tempfile::tempdir().unwrap().keep()).unwrap();

    let out_a = build::build(&store_a, ctx.path(), kilnfile).expect("build on store A");
    let out_b = build::build(&store_b, ctx.path(), kilnfile).expect("build on store B");

    assert_eq!(out_a.image_id, out_b.image_id, "same Kilnfile + sources must hash identically");

    let image_a = Image::load(&store_a, &out_a.image_id).unwrap();
    let image_b = Image::load(&store_b, &out_b.image_id).unwrap();
    assert_eq!(image_a.layers, image_b.layers, "layer ids, not just the final image id, must match");
}
