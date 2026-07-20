use crate::store::Hash;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("syscall {call} on {path:?} failed: {source}")]
    Syscall {
        call: &'static str,
        path: PathBuf,
        #[source]
        source: nix::Error,
    },

    #[error("invalid content hash {0:?}")]
    InvalidHash(String),

    #[error("blob {0} referenced but not present in the store")]
    MissingBlob(Hash),

    #[error("layer {0} not found")]
    LayerNotFound(Hash),

    #[error("image {0} not found")]
    ImageNotFound(String),

    #[error("Kilnfile parse error at line {line}: {message}")]
    KilnfileParse { line: usize, message: String },

    #[error("build failed: {0}")]
    Build(String),

    #[error("registry error: {0}")]
    Registry(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("runtime error: {0}")]
    Runtime(#[from] kilnd_core::Error),

    #[error("JSON error on {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
        let path = path.into();
        move |source| Error::Io { path, source }
    }

    pub fn json(path: impl Into<PathBuf>) -> impl FnOnce(serde_json::Error) -> Error {
        let path = path.into();
        move |source| Error::Json { path, source }
    }

    pub fn syscall(call: &'static str, path: impl Into<PathBuf>) -> impl FnOnce(nix::Error) -> Error {
        let path = path.into();
        move |source| Error::Syscall { call, path, source }
    }
}
