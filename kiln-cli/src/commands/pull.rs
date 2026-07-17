use crate::error::CliResult;
use kiln_image::registry;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Image reference, e.g. `busybox`, `busybox:1.36`, `library/debian:bookworm`
    pub image: String,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let id = registry::pull(store, &args.image)?;
    println!("{id}");
    Ok(())
}
