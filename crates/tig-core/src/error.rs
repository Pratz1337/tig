use crate::id::ObjectId;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("object {0} not found")]
    NotFound(ObjectId),
    #[error("object {id} is corrupt: {reason}")]
    Corrupt { id: ObjectId, reason: String },
    #[error("cannot decode {what}: {reason}")]
    Decode { what: &'static str, reason: String },
    #[error("expected a {expected} object, found {found}")]
    WrongKind { expected: &'static str, found: &'static str },
    #[error("invalid path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn decode(what: &'static str, reason: impl Into<String>) -> Self {
        Error::Decode { what, reason: reason.into() }
    }
}
