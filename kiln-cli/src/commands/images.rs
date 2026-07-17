use crate::error::CliResult;
use kiln_image::image::Image;
use kiln_image::store::Store;
use std::collections::HashSet;

#[derive(clap::Args, Debug)]
pub struct Args {}

pub fn run(store: &Store, _args: Args) -> CliResult {
    println!("{:<32}{:<12}{:<66}LAYERS", "REPOSITORY", "TAG", "IMAGE ID");

    let mut seen = HashSet::new();
    for (repo_name, tag_name, id) in store.all_tags() {
        seen.insert(id);
        let layers = Image::load(store, &id).map(|i| i.layers.len()).unwrap_or(0);
        println!("{repo_name:<32}{tag_name:<12}{id:<66}{layers}");
    }

    for id in store.all_image_ids() {
        if seen.contains(&id) {
            continue;
        }
        let layers = Image::load(store, &id).map(|i| i.layers.len()).unwrap_or(0);
        println!("{:<32}{:<12}{id:<66}{layers}", "<none>", "<none>");
    }

    Ok(())
}
