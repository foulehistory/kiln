//! `kiln key` - local ed25519 identity for image signing. See
//! `kiln_image::signing` for where the keypair actually lives and how
//! it's used; this is just the CLI surface over it.

use crate::error::{CliError, CliResult};
use kiln_image::signing;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Generate a new signing keypair at ~/.kiln/key/ (refuses to
    /// overwrite an existing one unless --force is given)
    Generate {
        #[arg(long)]
        force: bool,
    },
}

pub fn run(cmd: Command) -> CliResult {
    match cmd {
        Command::Generate { force } => {
            if signing::private_key_path().exists() && !force {
                return Err(CliError::msg(format!(
                    "a signing key already exists at {} - pass --force to overwrite (this orphans anything already published under the old key's public counterpart)",
                    signing::private_key_path().display()
                )));
            }
            signing::generate_and_save()?;
            println!("{}", signing::public_key_path().display());
        }
    }
    Ok(())
}
