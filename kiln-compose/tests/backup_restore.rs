//! `kiln-compose backup`/`restore` round-trip: a project's `kiln.yaml` and
//! its declared volumes' contents must survive being archived and restored
//! into a brand new store/directory (a different machine, in practice) -
//! and a secret referenced by the project must be named in `restore`'s
//! output, never bundled into the archive itself (see `backup.rs`'s module
//! docs on why). No root needed: backup/restore only touches plain files
//! under the store, no containers/networks/namespaces involved.

use kiln_image::store::Store;
use std::process::Command;

#[test]
fn backup_then_restore_round_trips_the_compose_file_and_volume_contents_without_the_secret_value() {
    let source_store_dir = tempfile::tempdir().unwrap();
    let source_store = Store::open(source_store_dir.path()).unwrap();

    let project_dir = tempfile::tempdir().unwrap();
    let kiln_yaml = "services:\n  web:\n    image: scratch\n    command: [\"/bin/sh\"]\n    volumes:\n      - webdata:/data\n    secrets:\n      - webtoken\nvolumes:\n  webdata: {}\n";
    std::fs::write(project_dir.path().join("kiln.yaml"), kiln_yaml).unwrap();

    // Simulates a volume that already has real data in it, without going
    // through a running container - `up` never runs here at all, so this
    // is the only way to give `backup` something real to archive.
    let volume_dir = source_store.root().join("volumes").join("webdata");
    std::fs::create_dir_all(&volume_dir).unwrap();
    std::fs::write(volume_dir.join("testfile.txt"), b"hello-from-backup-test").unwrap();

    let bin = env!("CARGO_BIN_EXE_kiln-compose");
    let backup_output = Command::new(bin)
        .args([
            "--store",
            source_store_dir.path().to_str().unwrap(),
            "-f",
            "kiln.yaml",
            "-p",
            "backuptest",
            "backup",
        ])
        .current_dir(project_dir.path())
        .output()
        .expect("spawn kiln-compose backup");
    assert!(
        backup_output.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&backup_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&backup_output.stdout);
    assert!(
        stdout.contains("webtoken"),
        "backup should list the referenced secret name in its output: {stdout}"
    );

    let archive_path = std::fs::read_dir(project_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("tar"))
        .expect("backup should have written a .kiln-backup.tar file");

    // A brand new store and a brand new directory - standing in for a
    // completely different machine, which is the whole point of `restore`.
    let dest_store_dir = tempfile::tempdir().unwrap();
    let dest_store = Store::open(dest_store_dir.path()).unwrap();
    let restore_dir = tempfile::tempdir().unwrap();

    let restore_output = Command::new(bin)
        .args(["--store", dest_store_dir.path().to_str().unwrap(), "restore"])
        .arg(&archive_path)
        .args(["--dest", restore_dir.path().to_str().unwrap()])
        .output()
        .expect("spawn kiln-compose restore");
    assert!(
        restore_output.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restore_output.stderr)
    );

    let restore_stdout = String::from_utf8_lossy(&restore_output.stdout);
    assert!(
        restore_stdout.contains("webtoken") && restore_stdout.contains("kiln secret create webtoken"),
        "restore should tell the operator to recreate the secret by hand: {restore_stdout}"
    );

    let restored_yaml = std::fs::read_to_string(restore_dir.path().join("kiln.yaml")).unwrap();
    assert_eq!(restored_yaml, kiln_yaml, "restore should write back the exact same kiln.yaml bytes");

    let restored_file = dest_store.root().join("volumes").join("webdata").join("testfile.txt");
    let restored_content = std::fs::read_to_string(&restored_file).expect("restore should have recreated the volume's file");
    assert_eq!(restored_content, "hello-from-backup-test");

    // The archive itself must only ever record the secret's *name* - there
    // is no ciphertext, key material, or anything else secret-shaped
    // anywhere in it, not just an omission from the printed summary above.
    let archive_bytes = std::fs::read(&archive_path).unwrap();
    let mut tar = tar::Archive::new(archive_bytes.as_slice());
    let entry_names: Vec<String> = tar
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entry_names,
        vec!["manifest.json", "kiln.yaml", "volumes/webdata.tar.gz"],
        "archive should contain exactly these three entries - nothing secret-shaped"
    );
}
