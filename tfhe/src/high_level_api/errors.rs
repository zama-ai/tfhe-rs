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
