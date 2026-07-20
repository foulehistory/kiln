use crate::error::CliResult;
use kiln_image::registry;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Image reference, e.g. `busybox`, `busybox:1.36`, `library/debian:bookworm`
    pub image: String,
    /// Skip signature verification (only meaningful for an explicit-host
    /// registry with signing configured - Docker Hub pulls are never
    /// affected either way). Off by default: an unsigned or invalidly
    /// signed image from a registry that has signatures at all is
    /// refused, not silently accepted.
    #[arg(long)]
    pub insecure_skip_verify: bool,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let id = registry::pull(store, &args.image, args.insecure_skip_verify)?;
    println!("{id}");
    Ok(())
}
