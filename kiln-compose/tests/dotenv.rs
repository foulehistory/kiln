//! Real-process proof that `.env` interpolation is actually wired into
//! `main.rs` (the pure substitution logic itself is covered exhaustively
//! and fast by `dotenv.rs`'s own unit tests) - drives the real compiled
//! binary as a subprocess, same convention as `tests/down.rs`. Uses `ps`
//! rather than `up`: it still fully parses (and therefore interpolates)
//! `kiln.yaml`, but does none of `up`'s privileged bridge/namespace work,
//! so this test needs no root.

use kiln_image::store::Store;
use std::process::Command;

fn write_project(dir: &std::path::Path, kiln_yaml: &str, dotenv: Option<&str>) {
    std::fs::write(dir.join("kiln.yaml"), kiln_yaml).unwrap();
    if let Some(dotenv) = dotenv {
        std::fs::write(dir.join(".env"), dotenv).unwrap();
    }
}

fn run_ps(store_dir: &std::path::Path, project_dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kiln-compose"))
        .args(["--store", store_dir.to_str().unwrap(), "-f", "kiln.yaml", "-p", "dotenvtest", "ps"])
        .current_dir(project_dir)
        .output()
        .expect("spawn kiln-compose")
}

/// `image:` deliberately doesn't need to resolve to a real, pullable
/// image - `ps` never resolves it, just parses and prints the service
/// list, so an interpolation-required placeholder can live there safely.
const KILN_YAML: &str = "services:\n  svc:\n    image: \"busybox:${TAG:?TAG must be set}\"\n";

#[test]
fn missing_required_variable_fails_the_whole_command() {
    let store_dir = tempfile::tempdir().unwrap();
    let _store = Store::open(store_dir.path()).unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    write_project(project_dir.path(), KILN_YAML, None);

    let output = run_ps(store_dir.path(), project_dir.path());
    assert!(!output.status.success(), "ps should fail when a required ${{VAR:?...}} is unresolved");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TAG must be set"),
        "expected the ${{:?message}} text in stderr, got: {stderr:?}"
    );
}

#[test]
fn dotenv_file_next_to_kiln_yaml_resolves_the_required_variable() {
    let store_dir = tempfile::tempdir().unwrap();
    let _store = Store::open(store_dir.path()).unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    write_project(project_dir.path(), KILN_YAML, Some("TAG=latest\n"));

    let output = run_ps(store_dir.path(), project_dir.path());
    assert!(
        output.status.success(),
        "ps should succeed once .env supplies TAG: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("svc"), "expected the parsed service to show up in ps output: {stdout:?}");
}
