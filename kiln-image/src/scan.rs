//! Vulnerability scanning: materializes an image's full layer stack into
//! a real overlayfs merge (the same mechanism `kiln run` itself uses to
//! assemble a rootfs, minus any process/namespace isolation - this only
//! ever reads files off it, never executes anything from the image),
//! then shells out to [Trivy](https://github.com/aquasecurity/trivy)
//! against that merged view.
//!
//! Deliberately not bundled, not reimplemented: accurately matching
//! installed package versions against known CVEs needs a maintained
//! vulnerability database (NVD, distro security trackers, ...) that's a
//! project of its own - Trivy already does this well. Kiln just
//! orchestrates it and keeps a compact summary of its output. Requires
//! `trivy` on `$PATH` - a real, separately-installed dependency, not
//! something Kiln bundles or checks for at build time.

use crate::error::{Error, Result};
use crate::identity;
use crate::image::Image;
use crate::layer;
use crate::store::{Hash, Store};
use kilnd_core::rootfs::{mount_overlay, unmount, OverlaySpec};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }
}

// --- Trivy's own JSON schema - only the fields Kiln actually reads;
// serde ignores everything else Trivy's real output includes. ---

#[derive(Deserialize, Default)]
struct TrivyOutput {
    #[serde(default, rename = "Results")]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(default, rename = "Vulnerabilities")]
    vulnerabilities: Vec<TrivyVulnerability>,
}

#[derive(Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(default, rename = "FixedVersion")]
    fixed_version: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(default, rename = "PrimaryURL")]
    primary_url: String,
}

/// Materializes `image_id`'s full layer stack into a throwaway overlayfs
/// merge and runs `trivy rootfs` against it.
pub fn scan(store: &Store, image_id: &Hash) -> Result<ScanReport> {
    let image = Image::load(store, image_id)?;
    let uid_base = identity::SUBORDINATE_UID_BASE;
    let gid_base = identity::SUBORDINATE_GID_BASE;

    let mut lower_dirs = Vec::new();
    for lid in image.lower_dirs_order() {
        lower_dirs.push(layer::materialize_cached(store, lid, uid_base, gid_base)?);
    }
    if lower_dirs.is_empty() {
        return Err(Error::Scan("cannot scan an image with no layers".into()));
    }

    let scratch = tempfile::tempdir().map_err(Error::io(std::env::temp_dir()))?;
    let upper = scratch.path().join("upper");
    let work = scratch.path().join("work");
    let merged = scratch.path().join("merged");
    for d in [&upper, &work, &merged] {
        std::fs::create_dir_all(d).map_err(Error::io(d))?;
    }

    let overlay = OverlaySpec {
        lower_dirs,
        upper_dir: upper,
        work_dir: work,
        merged_dir: merged.clone(),
    };
    mount_overlay(&overlay)?;
    let result = run_trivy(&merged);
    // Best-effort: a failed unmount here would otherwise mask whatever
    // `run_trivy` itself returned, and the scratch dir is deleted right
    // after regardless (tempdir's own Drop) - a leaked mount pointed at a
    // directory about to disappear is a worse failure mode to hide behind
    // than just logging it.
    if let Err(e) = unmount(&merged) {
        eprintln!("kiln: unmounting scan overlay: {e}");
    }

    result
}

fn run_trivy(target: &Path) -> Result<ScanReport> {
    let output = Command::new("trivy")
        .args(["rootfs", "--format", "json", "--quiet", "--scanners", "vuln"])
        .arg(target)
        .output()
        .map_err(|e| {
            Error::Scan(format!(
                "running trivy: {e} - is it installed? see https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            ))
        })?;

    if !output.status.success() {
        return Err(Error::Scan(format!(
            "trivy exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let parsed: TrivyOutput = serde_json::from_slice(&output.stdout).map_err(|e| Error::Scan(format!("parsing trivy output: {e}")))?;

    let mut report = ScanReport::default();
    for result in parsed.results {
        for v in result.vulnerabilities {
            match v.severity.as_str() {
                "CRITICAL" => report.critical += 1,
                "HIGH" => report.high += 1,
                "MEDIUM" => report.medium += 1,
                "LOW" => report.low += 1,
                _ => {}
            }
            report.findings.push(Finding {
                id: v.vulnerability_id,
                package: v.pkg_name,
                installed_version: v.installed_version,
                fixed_version: if v.fixed_version.is_empty() { None } else { Some(v.fixed_version) },
                severity: v.severity,
                url: if v.primary_url.is_empty() { None } else { Some(v.primary_url) },
            });
        }
    }
    Ok(report)
}
