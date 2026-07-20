//! Pulls a real, small public image from Docker Hub and proves the whole
//! pipeline connects: registry manifest/config parsing, OCI tar layer
//! conversion into Kiln's content-addressed format, and then actually
//! *using* the pulled image as a Kilnfile `FROM` base to run a real
//! command in a real container built from it.
//!
//! Needs outbound network access; skips (rather than failing the suite)
//! if Docker Hub isn't reachable, since that's an environment fact, not a
//! Kiln bug.

use kiln_image::build;
use kiln_image::image::Image;
use kiln_image::registry;
use kiln_image::store::Store;
use nix::unistd::Uid;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: pulling/materializing requires root in this environment");
        return false;
    }
    true
}

#[test]
fn pull_busybox_and_build_from_it() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let image_id = match registry::pull(&store, "busybox:latest", false) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("skipping: could not pull busybox from Docker Hub: {e}");
            return;
        }
    };

    let image = Image::load(&store, &image_id).expect("load pulled image");
    assert!(!image.layers.is_empty(), "busybox should have at least one layer");
    println!(
        "pulled busybox:latest -> image {image_id}, {} layer(s), cmd={:?}",
        image.layers.len(),
        image.config.cmd
    );

    // Tagging happens as a side effect of pull.
    let resolved = Image::resolve(&store, "busybox:latest").expect("resolve by tag");
    assert_eq!(resolved.id(), image_id);
    let resolved_by_hash = Image::resolve(&store, &image_id.to_string()).expect("resolve by hash");
    assert_eq!(resolved_by_hash.id(), image_id);

    // The real end-to-end proof: use the pulled image as a build base and
    // actually run something in it via kilnd-core.
    let ctx = tempfile::tempdir().unwrap();
    let kilnfile = "\
FROM busybox:latest
RUN echo pulled-and-ran > /proof.txt && busybox cat /proof.txt
";
    let output = build::build(&store, ctx.path(), kilnfile).expect("build FROM pulled image");
    assert!(!output.steps[0].cached);

    let built = Image::load(&store, &output.image_id).unwrap();
    assert_eq!(built.layers.len(), image.layers.len() + 1, "base layers plus one new RUN layer");

    let new_layer_id = *built.layers.last().unwrap();
    let dir = kiln_image::layer::materialize_cached(
        &store,
        &new_layer_id,
        kiln_image::identity::SUBORDINATE_UID_BASE,
        kiln_image::identity::SUBORDINATE_GID_BASE,
    )
    .unwrap();
    let proof = std::fs::read_to_string(dir.join("proof.txt")).expect("proof.txt written by RUN inside busybox");
    assert_eq!(proof.trim(), "pulled-and-ran");
}
