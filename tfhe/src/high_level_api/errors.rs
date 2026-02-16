use crate::Error;
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
             Did you forget to call `set_server_key` in the current thread ?\
            ",
        )
    }
}

impl std::error::Error for UninitializedServerKey {}

impl From<UninitializedServerKey> for Error {
    fn from(value: UninitializedServerKey) -> Self {
        Self::new(format!("{value}"))
    }
}

#[derive(Debug)]
pub struct UninitializedNoiseSquashing;

impl Display for UninitializedNoiseSquashing {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Noise squashing key not set in server key, \
            did you forget to call `enable_noise_squashing` when building your Config?",
        )
    }
}

impl std::error::Error for UninitializedNoiseSquashing {}

impl From<UninitializedNoiseSquashing> for Error {
    fn from(value: UninitializedNoiseSquashing) -> Self {
        Self::new(format!("{value}"))
    }
}

#[derive(Debug)]
pub struct UninitializedReRandKey;

impl Display for UninitializedReRandKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "No key available to perform \
              CompactPublicKey re-randomization. Did you forget to call \
              enable_ciphertext_re_randomization on your Config?"
        )
    }
}

impl From<UninitializedReRandKey> for Error {
    fn from(value: UninitializedReRandKey) -> Self {
        Self::new(format!("{value}"))
    }
}

impl std::error::Error for UninitializedReRandKey {}

#[derive(Debug)]
pub struct UninitializedCompressionKey;

impl Display for UninitializedCompressionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compression key is not set in server key, \
            did you forget to call `enable_compression` when building your Config?",
        )
    }
}

impl std::error::Error for UninitializedCompressionKey {}

impl From<UninitializedCompressionKey> for Error {
    fn from(value: UninitializedCompressionKey) -> Self {
        Self::new(format!("{value}"))
    }
}

#[derive(Debug)]
pub struct UninitializedDecompressionKey;

impl Display for UninitializedDecompressionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Decompression key is not set in server key, \
            did you forget to call `enable_compression` when building your Config?",
        )
    }
}

impl std::error::Error for UninitializedDecompressionKey {}

impl From<UninitializedDecompressionKey> for Error {
    fn from(value: UninitializedDecompressionKey) -> Self {
        Self::new(format!("{value}"))
    }
}
