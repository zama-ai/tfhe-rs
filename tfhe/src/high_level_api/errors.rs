use std::fmt::{Display, Formatter};

/// Unwrap 'Extension' trait
///
/// The goal of this trait is to add a method similar to `unwrap` to `Result<T, E>`
/// that uses the implementation of `Display` and not `Debug` as the
/// message in the panic.
pub trait UnwrapResultExt<T> {
    fn unwrap_display(self) -> T;
}

impl<T, E> UnwrapResultExt<T> for Result<T, E>
where
    E: Display,
{
    #[track_caller]
    fn unwrap_display(self) -> T {
        match self {
            Ok(t) => t,
            Err(e) => panic!("{}", e),
        }
    }
}

/// The server key was not initialized
#[derive(Debug)]
pub struct UninitializedServerKey;

impl Display for UninitializedServerKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The server key was not properly initialized.\n\
             Did you forget to call `set_server_key` in the current thread ?
            ",
        )
    }
}

impl std::error::Error for UninitializedServerKey {}

/// Error when trying to create a short integer from a value that was too big to be represented
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OutOfRangeError;

impl Display for OutOfRangeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value is out of range")
    }
}

impl std::error::Error for OutOfRangeError {}

#[non_exhaustive]
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    OutOfRange,
    UninitializedServerKey,
}

impl From<OutOfRangeError> for Error {
    fn from(_: OutOfRangeError) -> Self {
        Self::OutOfRange
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange => {
                write!(f, "{OutOfRangeError}")
            }
            Self::UninitializedServerKey => {
                write!(f, "{UninitializedServerKey}")
            }
        }
    }
}

impl std::error::Error for Error {}
