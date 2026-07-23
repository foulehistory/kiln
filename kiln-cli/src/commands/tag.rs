//! `kiln tag` - point a new `name[:tag]` at an already-built/pulled
//! image, without copying anything (tags are cheap pointers - see
//! `kiln_image::store::Store::tag`'s own docs). The one missing step
//! that made `kiln push registry.example.com/you/app:latest` resolve
//! "no such image" for anything not already tagged under that exact
//! name: `kiln push`/`kilnd`'s push endpoint only ever push whatever a
//! reference already resolves to locally, they never rename on the fly.

use crate::error::{CliError, CliResult};
use kiln_image::image::{tag_reference, Image};
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Existing local reference (`name:tag` or a bare image id) to tag under a new name
    pub source: String,
    /// New `name[:tag]` to point at the same image (`:tag` defaults to `latest`)
    pub target: String,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let image = Image::resolve(store, &args.source).map_err(|e| CliError::msg(format!("resolving {}: {e}", args.source)))?;
    let id = image.save(store).map_err(|e| CliError::msg(format!("{e}")))?;
    tag_reference(store, &id, &args.target).map_err(|e| CliError::msg(format!("tagging {}: {e}", args.target)))?;
    println!("{}", args.target);
    Ok(())
}
