use crate::error::{CliError, CliResult};
use kiln_image::image::Image;
use kiln_image::registry;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Local image reference to push, e.g. `myapp:latest` or an image ID.
    /// Pushed to the registry under this same name.
    pub image: String,

    /// Scan for known vulnerabilities before pushing (requires `trivy` on
    /// $PATH) and attach the report to the pushed manifest - never
    /// automatic, unlike signing.
    #[arg(long)]
    pub scan: bool,

    /// Refuse to push if the scan finds any CRITICAL-severity
    /// vulnerability. Implies --scan.
    #[arg(long)]
    pub block_on_critical: bool,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let image = Image::resolve(store, &args.image).map_err(|e| CliError::msg(format!("resolving {}: {e}", args.image)))?;
    let id = image.save(store).map_err(|e| CliError::msg(format!("{e}")))?;

    let mut report = None;
    if args.scan || args.block_on_critical {
        println!("Scanning {} ({id}) before push...", args.image);
        let r = kiln_image::scan::scan(store, &id).map_err(|e| CliError::msg(format!("{e}")))?;
        store.save_scan_report(id, &r).map_err(|e| CliError::msg(format!("{e}")))?;
        crate::commands::image::print_report(&r);
        if args.block_on_critical && r.critical > 0 {
            let ids: Vec<&str> = r.findings.iter().filter(|f| f.severity == "CRITICAL").map(|f| f.id.as_str()).collect();
            return Err(CliError::msg(format!(
                "push blocked: {} critical vulnerabilit{} found ({}) - re-run without --block-on-critical to push anyway",
                r.critical,
                if r.critical == 1 { "y" } else { "ies" },
                ids.join(", ")
            )));
        }
        report = Some(r);
    }

    registry::push(store, &id, &args.image).map_err(|e| CliError::msg(format!("push failed: {e}")))?;
    println!("pushed {} as {}", id, args.image);

    if let Some(r) = report {
        registry::push_scan_report(&args.image, &r).map_err(|e| CliError::msg(format!("pushed image, but publishing scan report failed: {e}")))?;
    }
    Ok(())
}
