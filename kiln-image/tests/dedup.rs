//! Verifies the actual point of file-level (not just layer-level) content
//! addressing: two completely unrelated layers that happen to share a
//! file's exact bytes must occupy exactly one blob on disk, and
//! materializing both must not corrupt either one's independently-set
//! permissions/ownership (see `store.rs`'s `place_blob` docs for why that
//! second part is the tricky part).

use kiln_image::layer::{materialize, Entry, EntryKind, LayerManifest};
use kiln_image::store::Store;
use nix::unistd::Uid;
use std::fs;
use walkdir::WalkDir;

fn require_root() -> bool {
    if !Uid::effective().is_root() {
        eprintln!("skipping: materializing with arbitrary uid/gid requires root in this environment");
        return false;
    }
    true
}

fn count_blobs(store: &Store) -> usize {
    WalkDir::new(store.root().join("blobs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

#[test]
fn identical_file_content_across_layers_is_stored_once() {
    if !require_root() {
        return;
    }

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();

    let shared_content = b"this exact content appears in two unrelated layers\n";

    // Layer A: some file at one path, owned root:root.
    let blob_a = store.put_bytes(shared_content).unwrap();
    let manifest_a = LayerManifest {
        entries: vec![Entry {
            path: "usr/share/common.txt".into(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            kind: EntryKind::File { blob: blob_a, size: shared_content.len() as u64 },
        }],
    };
    manifest_a.save(&store).unwrap();

    // Layer B: the *same bytes*, different path, different metadata -
    // as if two completely unrelated images both happened to ship an
    // identical file with different ownership.
    let blob_b = store.put_bytes(shared_content).unwrap();
    assert_eq!(blob_a, blob_b, "identical content must hash identically");

    let manifest_b = LayerManifest {
        entries: vec![Entry {
            path: "opt/other/copy.txt".into(),
            mode: 0o600,
            uid: 1000,
            gid: 1000,
            kind: EntryKind::File { blob: blob_b, size: shared_content.len() as u64 },
        }],
    };
    manifest_b.save(&store).unwrap();

    assert_eq!(count_blobs(&store), 1, "one blob, regardless of how many layers reference it");

    // Materialize both layers and confirm each keeps its OWN metadata
    // despite sharing an inode's worth of content.
    let base = kiln_image::identity::SUBORDINATE_UID_BASE;
    let gbase = kiln_image::identity::SUBORDINATE_GID_BASE;

    let dest_a = store_dir.path().join("materialized-a");
    materialize(&manifest_a, &store, &dest_a, base, gbase).unwrap();
    let dest_b = store_dir.path().join("materialized-b");
    materialize(&manifest_b, &store, &dest_b, base, gbase).unwrap();

    let content_a = fs::read(dest_a.join("usr/share/common.txt")).unwrap();
    let content_b = fs::read(dest_b.join("opt/other/copy.txt")).unwrap();
    assert_eq!(content_a, shared_content);
    assert_eq!(content_b, shared_content);

    use std::os::unix::fs::MetadataExt;
    let meta_a = fs::metadata(dest_a.join("usr/share/common.txt")).unwrap();
    let meta_b = fs::metadata(dest_b.join("opt/other/copy.txt")).unwrap();
    assert_eq!(meta_a.mode() & 0o7777, 0o644);
    assert_eq!(meta_a.uid(), base);
    assert_eq!(meta_b.mode() & 0o7777, 0o600);
    assert_eq!(meta_b.uid(), base + 1000);
    assert_ne!(
        (meta_a.mode() & 0o7777, meta_a.uid()),
        (meta_b.mode() & 0o7777, meta_b.uid()),
        "sharing a blob must not leak one placement's metadata onto the other"
    );
}
