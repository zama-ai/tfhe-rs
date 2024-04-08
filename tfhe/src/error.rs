use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    Message(String),
    /// The zero knowledge proof and the content it is supposed to prove
    /// failed to correctly prove
    #[cfg(feature = "zk-pok-experimental")]
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
            #[cfg(feature = "zk-pok-experimental")]
            ErrorKind::InvalidZkProof => {
                write!(f, "The zero knowledge proof and the content it is supposed to prove were not valid")
            }
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

impl std::error::Error for Error {}
