//! `kiln gc` mark-and-sweep: a blob shared between a tagged and an
//! untagged image must survive (still reachable via the tag), while a
//! blob only the untagged image references - and the untagged image's
//! own manifest - must not.

use kiln_cli::commands::gc::collect_garbage;
use kiln_image::image::{Image, ImageConfig};
use kiln_image::layer::{Entry, EntryKind, LayerManifest};
use kiln_image::store::Store;

fn layer_with_file(store: &Store, path: &str, content: &[u8]) -> kiln_image::store::Hash {
    let blob = store.put_bytes(content).unwrap();
    let manifest = LayerManifest {
        entries: vec![Entry {
            path: path.to_string(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            kind: EntryKind::File { blob, size: content.len() as u64 },
        }],
    };
    manifest.save(store).unwrap()
}

#[test]
fn gc_keeps_blobs_reachable_from_a_tag_and_removes_the_rest() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let shared_content = b"shared between both images";
    let a_only_content = b"only image A has this file";
    let b_only_content = b"only image B has this file";

    let shared_layer = layer_with_file(&store, "shared.txt", shared_content);
    let a_layer = layer_with_file(&store, "a-only.txt", a_only_content);
    let b_layer = layer_with_file(&store, "b-only.txt", b_only_content);

    let shared_blob = kiln_image::store::Hash::of_bytes(shared_content);
    let a_blob = kiln_image::store::Hash::of_bytes(a_only_content);
    let b_blob = kiln_image::store::Hash::of_bytes(b_only_content);

    let image_a = Image { layers: vec![shared_layer, a_layer], config: ImageConfig::default() };
    let image_a_id = image_a.save(&store).unwrap();
    store.tag("library/kept", "latest", image_a_id).unwrap();

    let image_b = Image { layers: vec![shared_layer, b_layer], config: ImageConfig::default() };
    let image_b_id = image_b.save(&store).unwrap();
    // Deliberately never tagged - this is the `<none>` orphan case.

    assert!(store.has_blob(&shared_blob));
    assert!(store.has_blob(&a_blob));
    assert!(store.has_blob(&b_blob));

    let summary = collect_garbage(&store);

    assert_eq!(summary.blobs_removed, 1, "only image B's own blob should be swept");
    assert_eq!(summary.images_removed, 1, "only image B's untagged manifest should be swept");

    assert!(store.has_blob(&shared_blob), "shared blob is still reachable via image A's tag");
    assert!(store.has_blob(&a_blob), "image A's own blob is reachable via its tag");
    assert!(!store.has_blob(&b_blob), "image B's own blob is unreachable once B is untagged");

    assert!(Image::load(&store, &image_a_id).is_ok(), "tagged image A survives");
    assert!(Image::load(&store, &image_b_id).is_err(), "untagged image B's manifest is removed");
}
