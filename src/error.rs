use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{path}: {source}", path = path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("gpg: {0}")]
    Gpg(String),

    #[error("parse: {0}")]
    Parse(String),

    #[error("corrupt key at {path}: {detail}", path = path.display())]
    Corrupt { path: PathBuf, detail: String },

    #[error("certificate: {0}")]
    Certificate(String),

    #[error("nota: {0}")]
    Nota(#[from] nota_codec::Error),

    #[error("inline Nota argument must be UTF-8: {got}")]
    InvalidInlineNotaArgument { got: String },
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Parse(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Parse(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
