//! One error type for the whole program. Every variant's message is written to be read by
//! the model or the user, so it says what to do next where that is possible.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request itself is wrong (bad argument, unknown account, unknown folder).
    #[error("{0}")]
    Invalid(String),

    /// The configuration or policy file is missing, malformed or not trustworthy.
    #[error("configuration problem: {0}")]
    Config(String),

    /// Signing in to the mail provider failed or needs the user.
    #[error("{0}")]
    Auth(String),

    /// The action was not approved, or policy forbids it.
    #[error("{0}")]
    Denied(String),

    #[error("mail server (IMAP) error: {0}")]
    Imap(#[from] async_imap::error::Error),

    #[error("sending (SMTP) failed: {0}")]
    #[cfg_attr(test, allow(dead_code))]
    Smtp(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("timed out while {0}")]
    Timeout(&'static str),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::Denied(message.into())
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth(message.into())
    }
}

/// Attach a short description of what was being done to an I/O error.
pub trait IoContext<T> {
    fn io_context(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn io_context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: context.into(),
            source,
        })
    }
}

/// A bare I/O error with no better description is a network failure: file operations
/// always attach their own context through [`IoContext`].
impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::Network(source.to_string())
    }
}
