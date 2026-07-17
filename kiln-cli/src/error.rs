#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Image(#[from] kiln_image::Error),
    #[error("{0}")]
    Runtime(#[from] kilnd_core::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}

impl CliError {
    pub fn msg(s: impl Into<String>) -> Self {
        CliError::Message(s.into())
    }
}

pub type CliResult<T = ()> = std::result::Result<T, CliError>;
