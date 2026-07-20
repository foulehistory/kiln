//! `kiln image` - operations on a single image, distinct from the
//! existing (plural, list-only) `kiln images` command, same split Docker
//! itself uses (`docker images` vs `docker image inspect/scan/...`).

use crate::error::CliResult;
use kiln_image::image::Image;
use kiln_image::scan::ScanReport;
use kiln_image::store::Store;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Scan an image for known vulnerabilities (requires `trivy` on
    /// $PATH - see kiln_image::scan's module docs)
    Scan { image: String },
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Scan { image } => {
            let img = Image::resolve(store, &image)?;
            let id = img.id();
            println!("Scanning {image} ({id})...");
            let report = kiln_image::scan::scan(store, &id)?;
            store.save_scan_report(id, &report)?;
            print_report(&report);
        }
    }
    Ok(())
}

pub fn print_report(report: &ScanReport) {
    println!();
    println!(
        "CRITICAL: {}  HIGH: {}  MEDIUM: {}  LOW: {}",
        report.critical, report.high, report.medium, report.low
    );
    if report.findings.is_empty() {
        println!("No known vulnerabilities found.");
        return;
    }
    println!();
    println!("{:<18}{:<24}{:<16}{:<16}ID", "SEVERITY", "PACKAGE", "INSTALLED", "FIXED");
    let mut findings = report.findings.clone();
    findings.sort_by_key(|f| severity_rank(&f.severity));
    for f in findings {
        println!(
            "{:<18}{:<24}{:<16}{:<16}{}",
            f.severity,
            f.package,
            f.installed_version,
            f.fixed_version.as_deref().unwrap_or("-"),
            f.id
        );
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}
