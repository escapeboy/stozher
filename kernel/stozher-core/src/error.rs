//! Errors carrying the specification's normative machine-readable codes.

use std::fmt;

/// A rejection, identified by the normative error code from the specification.
///
/// The `code` is part of the wire contract (`spec/00-overview.md` §1): a Python gateway and
/// a Rust kernel must refuse the same thing by the same name, and the test vectors assert on
/// these strings. `detail` is human-facing only and is never contractual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: &'static str,
    detail: String,
    seq: Option<u64>,
}

impl Error {
    /// Build an error with a normative code and a human-readable detail.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            seq: None,
        }
    }

    /// Attach the chain position at which verification failed.
    #[must_use]
    pub fn at_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// The normative error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable detail. Not contractual.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The chain position at which verification failed, when applicable.
    #[must_use]
    pub fn seq(&self) -> Option<u64> {
        self.seq
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.seq {
            Some(seq) => write!(f, "{} at seq {}: {}", self.code, seq, self.detail),
            None => write!(f, "{}: {}", self.code, self.detail),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Construct an [`Error`] with a formatted detail.
macro_rules! err {
    ($code:expr, $($arg:tt)*) => {
        $crate::error::Error::new($code, format!($($arg)*))
    };
}

pub(crate) use err;
