//! `kiln inspect` - full JSON dump of a container or image, for scripting
//! or debugging beyond what `kiln ps`/`kiln images`'s fixed-column tables
//! show.

use crate::container::Container;
use crate::error::{CliError, CliResult};
use kiln_image::image::Image;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// A container id/name, or an image reference/id
    pub target: String,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    if let Some(mut c) = Container::resolve(store, &args.target) {
        c.refresh(store);
        println!("{}", serde_json::to_string_pretty(&c).map_err(|e| CliError::msg(e.to_string()))?);
        return Ok(());
    }
    if let Ok(image) = Image::resolve(store, &args.target) {
        println!("{}", serde_json::to_string_pretty(&image).map_err(|e| CliError::msg(e.to_string()))?);
        return Ok(());
    }
    Err(CliError::msg(format!("no such container or image: {}", args.target)))
}
