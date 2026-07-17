use crate::error::{CliError, CliResult};
use kiln_image::image::Image;
use kiln_image::registry;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Local image reference to push, e.g. `myapp:latest` or an image ID.
    /// Pushed to the registry under this same name.
    pub image: String,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let image = Image::resolve(store, &args.image).map_err(|e| CliError::msg(format!("resolving {}: {e}", args.image)))?;
    let id = image.save(store).map_err(|e| CliError::msg(format!("{e}")))?;
    registry::push(store, &id, &args.image).map_err(|e| CliError::msg(format!("push failed: {e}")))?;
    println!("pushed {} as {}", id, args.image);
    Ok(())
}
