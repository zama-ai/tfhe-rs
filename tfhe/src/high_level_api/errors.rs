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

/// Enum that lists types available
///
/// Mainly used to provide good errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Type {
    #[cfg(feature = "boolean")]
    FheBool,
    #[cfg(feature = "shortint")]
    FheUint2,
    #[cfg(feature = "shortint")]
    FheUint3,
    #[cfg(feature = "shortint")]
    FheUint4,
    #[cfg(feature = "integer")]
    FheUint8,
    #[cfg(feature = "integer")]
    FheUint10,
    #[cfg(feature = "integer")]
    FheUint12,
    #[cfg(feature = "integer")]
    FheUint14,
    #[cfg(feature = "integer")]
    FheUint16,
    #[cfg(feature = "integer")]
    FheUint32,
    #[cfg(feature = "integer")]
    FheUint64,
    #[cfg(feature = "integer")]
    FheUint128,
    #[cfg(feature = "integer")]
    FheUint256,
    #[cfg(feature = "integer")]
    FheInt8,
    #[cfg(feature = "integer")]
    FheInt16,
    #[cfg(feature = "integer")]
    FheInt32,
    #[cfg(feature = "integer")]
    FheInt64,
    #[cfg(feature = "integer")]
    FheInt128,
    #[cfg(feature = "integer")]
    FheInt256,
}

/// The server key of a given type was not initialized
#[derive(Debug)]
pub struct UninitializedServerKey(pub(crate) Type);

impl Display for UninitializedServerKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The server key for the type '{:?}' was not properly initialized\n\
             Did you forget to call `set_server_key` in this thread or forget to
             enable the type in the config ?
            ",
            self.0
        )
    }
}

impl std::error::Error for UninitializedServerKey {}

/// The client key of a given type was not initialized
#[derive(Debug)]
pub struct UninitializedClientKey(pub(crate) Type);

impl Display for UninitializedClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The client key for the type '{:?}' was not properly initialized\n\
             Did you forget to enable the type in the config ?
            ",
            self.0
        )
    }
}

impl std::error::Error for UninitializedClientKey {}

/// The public key of a given type was not initialized
#[derive(Debug)]
pub struct UninitializedPublicKey(pub(crate) Type);

impl Display for UninitializedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The public key for the type '{:?}' was not properly initialized\n\
             Did you forget do enable the type in the config  ?
            ",
            self.0
        )
    }
}

impl std::error::Error for UninitializedPublicKey {}

/// The compresesd public key of a given type was not initialized
#[derive(Debug)]
pub struct UninitializedCompressedPublicKey(pub(crate) Type);

impl Display for UninitializedCompressedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The compressed public key for the type '{:?}' was not properly initialized\n\
             Did you forget do enable the type in the config  ?
            ",
            self.0
        )
    }
}

impl std::error::Error for UninitializedCompressedPublicKey {}

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
    UninitializedClientKey(Type),
    UninitializedPublicKey(Type),
    UninitializedServerKey(Type),
}

impl From<OutOfRangeError> for Error {
    fn from(_: OutOfRangeError) -> Self {
        Self::OutOfRange
    }
}

impl From<UninitializedClientKey> for Error {
    fn from(value: UninitializedClientKey) -> Self {
        Self::UninitializedClientKey(value.0)
    }
}

impl From<UninitializedPublicKey> for Error {
    fn from(value: UninitializedPublicKey) -> Self {
        Self::UninitializedPublicKey(value.0)
    }
}

impl From<UninitializedServerKey> for Error {
    fn from(value: UninitializedServerKey) -> Self {
        Self::UninitializedServerKey(value.0)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OutOfRange => {
                write!(f, "{OutOfRangeError}")
            }
            Error::UninitializedClientKey(ty) => {
                write!(f, "{}", UninitializedClientKey(*ty))
            }
            Error::UninitializedPublicKey(ty) => {
                write!(f, "{}", UninitializedPublicKey(*ty))
            }
            Error::UninitializedServerKey(ty) => {
                write!(f, "{}", UninitializedServerKey(*ty))
            }
        }
    }
}

impl std::error::Error for Error {}
