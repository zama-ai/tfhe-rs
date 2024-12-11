use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    Message(String),
    /// The provide range for a slicing operation was invalid
    InvalidRange(InvalidRangeError),
    /// The zero knowledge proof and the content it is supposed to prove
    /// failed to correctly prove
    #[cfg(feature = "zk-pok")]
    InvalidZkProof,
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) fn new(message: String) -> Self {
        Self::from(ErrorKind::Message(message))
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.kind() {
            ErrorKind::Message(msg) => {
                write!(f, "{msg}")
            }
            #[cfg(feature = "zk-pok")]
            ErrorKind::InvalidZkProof => {
                write!(f, "The zero knowledge proof and the content it is supposed to prove were not valid")
            }
            ErrorKind::InvalidRange(err) => write!(f, "Invalid range: {err}"),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl<'a> From<&'a str> for Error {
    fn from(message: &'a str) -> Self {
        Self::new(message.to_string())
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<InvalidRangeError> for Error {
    fn from(value: InvalidRangeError) -> Self {
        let kind = ErrorKind::InvalidRange(value);
        Self { kind }
    }
}

impl std::error::Error for Error {}

// This is useful to use infallible conversions as well as fallible ones in certain parts of the lib
impl From<std::convert::Infallible> for Error {
    fn from(_value: std::convert::Infallible) -> Self {
        // This can never be reached
        unreachable!()
    }
}

/// Error returned when the provided range for a slice is invalid
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InvalidRangeError {
    /// The upper bound of the range is greater than the size of the integer
    SliceTooBig,
    /// The upper gound is smaller than the lower bound
    WrongOrder,
}

impl Display for InvalidRangeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SliceTooBig => write!(
                f,
                "The upper bound of the range is greater than the size of the integer"
            ),
            Self::WrongOrder => {
                write!(f, "The upper gound is smaller than the lower bound")
            }
        }
    }
}

impl std::error::Error for InvalidRangeError {}
