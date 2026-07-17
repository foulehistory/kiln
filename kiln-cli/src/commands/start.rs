use crate::commands::run::restart;
use crate::error::CliResult;
use kiln_image::store::Store;

#[derive(clap::Args, Debug)]
pub struct Args {
    pub container: String,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let container = restart(store, &args.container)?;
    println!("{}", container.id);
    Ok(())
}
