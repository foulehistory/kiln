use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("syscall {call} failed: {source}")]
    Syscall {
        call: &'static str,
        #[source]
        source: nix::Error,
    },

    #[error("I/O error on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("child process reported setup failure: {0}")]
    ChildSetup(String),

    #[error("cgroup controller {0:?} not available under cgroup.controllers")]
    ControllerUnavailable(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn syscall(call: &'static str) -> impl Fn(nix::Error) -> Error {
    move |source| Error::Syscall { call, source }
}

pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}
