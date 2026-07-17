//! `kiln logs` - read (and optionally follow) a container's captured
//! output.
//!
//! Only detached (`-d`) containers capture logs in this version: a
//! foreground `kiln run` inherits the terminal's stdout/stderr directly
//! for genuinely live output, and nothing tees that to a file too.
//! Detached containers instead have stdout/stderr redirected to
//! `containers/<id>/log` at start time (see `commands::run`).

use crate::container::Container;
use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Duration;

#[derive(clap::Args, Debug)]
pub struct Args {
    pub container: String,
    /// Keep printing new output as it's written, like `tail -f`
    #[arg(short = 'f', long)]
    pub follow: bool,
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let container = Container::resolve(store, &args.container)
        .ok_or_else(|| CliError::msg(format!("no such container: {}", args.container)))?;
    let log_path = Container::log_path(store, &container.id);
    let mut file = File::open(&log_path).map_err(|e| {
        CliError::msg(format!(
            "no logs for {}: {e} (only detached `-d` containers capture logs)",
            container.id
        ))
    })?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| CliError::msg(e.to_string()))?;
    let mut stdout = std::io::stdout();
    stdout.write_all(&buf).ok();

    if args.follow {
        let mut pos = buf.len() as u64;
        loop {
            let len = file.metadata().map(|m| m.len()).unwrap_or(pos);
            if len > pos {
                file.seek(SeekFrom::Start(pos)).ok();
                let mut chunk = Vec::new();
                file.read_to_end(&mut chunk).ok();
                stdout.write_all(&chunk).ok();
                stdout.flush().ok();
                pos += chunk.len() as u64;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    Ok(())
}
