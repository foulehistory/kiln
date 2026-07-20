//! `kiln secret` - encrypted-at-rest values, mounted into a container as
//! a file (`/run/secrets/<name>`) rather than a plain `-e` environment
//! variable, which `kiln inspect`/`Container`'s own persisted state would
//! otherwise show in the clear forever. See `kiln_image::secrets` for the
//! actual encryption.

use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use std::io::Read;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Create (or overwrite) a secret. The value is read from stdin,
    /// never a command-line argument - a positional value would end up
    /// in shell history. e.g. `echo -n "hunter2" | kiln secret create
    /// admin-password`
    Create { name: String },
    /// List secret names - never values
    Ls,
    Rm { name: String },
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Create { name } => {
            let mut value = Vec::new();
            std::io::stdin().read_to_end(&mut value).map_err(CliError::from)?;
            // A trailing newline from `echo "..." | kiln secret create` is
            // almost never intended to be part of the secret itself -
            // `echo -n`/`printf` avoid it, but stripping one trailing `\n`
            // (and a `\r\n` on top of it) is a much friendlier default
            // than making every caller remember `-n`.
            if value.last() == Some(&b'\n') {
                value.pop();
                if value.last() == Some(&b'\r') {
                    value.pop();
                }
            }
            if value.is_empty() {
                return Err(CliError::msg("secret value must not be empty (nothing read from stdin)"));
            }
            kiln_image::secrets::create(store.root(), &name, &value)?;
            println!("{name}");
        }
        Command::Ls => {
            println!("SECRET NAME");
            for name in kiln_image::secrets::list(store.root()) {
                println!("{name}");
            }
        }
        Command::Rm { name } => {
            kiln_image::secrets::remove(store.root(), &name)?;
            println!("{name}");
        }
    }
    Ok(())
}
