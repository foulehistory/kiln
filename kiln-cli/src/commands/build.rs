use crate::error::{CliError, CliResult};
use kiln_image::build;
use kiln_image::image::{normalize_repository, split_name_tag};
use kiln_image::store::Store;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Tag to apply to the built image, e.g. myapp:latest
    #[arg(short = 't', long)]
    pub tag: Option<String>,

    /// Path to the Kilnfile (defaults to <context>/Kilnfile)
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,

    /// Build context directory
    pub context: PathBuf,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let kilnfile_path = args.file.unwrap_or_else(|| args.context.join("Kilnfile"));
    let source = std::fs::read_to_string(&kilnfile_path).map_err(|e| CliError::msg(format!("reading {}: {e}", kilnfile_path.display())))?;

    let output = build::build(store, &args.context, &source)?;
    for step in &output.steps {
        let marker = if step.cached { "CACHED" } else { "   RUN" };
        println!("[{marker}] {}", step.instruction);
    }
    println!("built: {}", output.image_id);

    if let Some(tag) = &args.tag {
        let (name, tag_name) = split_name_tag(tag);
        let repo = normalize_repository(name);
        store.tag(&repo, tag_name, output.image_id)?;
        println!("tagged: {repo}:{tag_name}");
    }
    Ok(())
}
