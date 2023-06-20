//! In this module, we store the hidden (to the end-user) internal state/keys that are needed to
//! perform operations.
use crate::high_level_api::errors::{UninitializedServerKey, UnwrapResultExt};
use std::cell::RefCell;

use crate::high_level_api::keys::ServerKey;

/// We store the internal keys as thread local, meaning each thread has its own set of keys.
///
/// This means that the user can do computations in multiple threads
/// (eg a web server that processes multiple requests in multiple threads).
/// The user however, has to initialize the internal keys each time it starts a thread.
thread_local! {
    static INTERNAL_KEYS: RefCell<ServerKey> = RefCell::new(ServerKey::default());
}

/// The function used to initialize internal keys.
///
/// As each thread has its own set of keys,
/// this function must be called at least once on each thread to initialize its keys.
///
///
/// # Example
///
/// Only working in the `main` thread
///
/// ```
/// use tfhe;
///
/// # let config = tfhe::ConfigBuilder::all_disabled().build();
/// let (client_key, server_key) = tfhe::generate_keys(config);
///
/// tfhe::set_server_key(server_key);
/// // Now we can do operations on homomorphic types
/// ```
///
///
/// Working with multiple threads
///
/// ```
/// use std::thread;
/// use tfhe;
/// use tfhe::ConfigBuilder;
///
/// # let config = tfhe::ConfigBuilder::all_disabled().build();
/// let (client_key, server_key) = tfhe::generate_keys(config);
/// let server_key_2 = server_key.clone();
///
/// let th1 = thread::spawn(move || {
///     tfhe::set_server_key(server_key);
///     // Now, this thread we can do operations on homomorphic types
/// });
///
/// let th2 = thread::spawn(move || {
///     tfhe::set_server_key(server_key_2);
///     // Now, this thread we can do operations on homomorphic types
/// });
///
/// th2.join();
/// th1.join();
/// ```
pub fn set_server_key(keys: ServerKey) {
    INTERNAL_KEYS.with(|internal_keys| internal_keys.replace_with(|_old| keys));
}

pub fn unset_server_key() -> ServerKey {
    INTERNAL_KEYS.with(|internal_keys| internal_keys.replace_with(|_old| Default::default()))
}

pub fn with_server_key_as_context<T, F>(keys: ServerKey, f: F) -> (T, ServerKey)
where
    F: FnOnce() -> T,
{
    set_server_key(keys);
    let result = f();
    let keys = unset_server_key();
    (result, keys)
}

/// Convenience function that allows to write functions that needs to access the internal keys.
#[cfg(any(feature = "integer", feature = "shortint", feature = "boolean"))]
#[inline]
pub(crate) fn with_internal_keys<T, F>(func: F) -> T
where
    F: FnOnce(&ServerKey) -> T,
{
    // Should use `with_borrow` when its stabilized
    INTERNAL_KEYS.with(|keys| {
        let key = &*keys.borrow();
        func(key)
    })
}

/// Helper macro to help reduce boiler plate
/// needed to implement `WithGlobalKey` since for
/// our keys, the implementation is the same, only a few things change.
///
/// It expects:
/// - The implementor type
/// - The  `name` of the key type for which the trait will be implemented.
/// - The identifier (or identifier chain) that points to the member in the `ServerKey` that holds
///   the key for which the trait is implemented.
/// - Type Variant used to identify the type at runtime (see `error.rs`)
#[cfg(any(feature = "integer", feature = "shortint", feature = "boolean"))]
macro_rules! impl_with_global_key {
    (
        for $implementor:ty {
            key_type: $key_type:ty,
            keychain_member: $($member:ident).*,
            type_variant: $enum_variant:expr,
        }
    ) => {
        impl crate::high_level_api::global_state::WithGlobalKey for $implementor {
            type Key = $key_type;

            fn with_global<R, F>(self, func: F) -> Result<R, crate::high_level_api::errors::UninitializedServerKey>
            where
                F: FnOnce(&Self::Key) -> R,
            {
                crate::high_level_api::global_state::with_internal_keys(|keys| {
                    keys$(.$member)*
                        .as_ref()
                        .map(func)
                        .ok_or(crate::high_level_api::errors::UninitializedServerKey($enum_variant))
                })
            }
        }
    }
}

/// Global key access trait
///
/// Each type we will expose to the user is going to need to have some internal keys.
/// This trait is there to make each of these internal keys have a convenience function that gives
/// access to the internal keys of its type.
///
/// Typically, the implementation of the trait will be on the 'internal' key type
/// and will call [with_internal_keys] and select the right member of the [ServerKey] type.
pub trait WithGlobalKey: Sized {
    type Key;

    fn with_global<R, F>(self, func: F) -> Result<R, UninitializedServerKey>
    where
        F: FnOnce(&Self::Key) -> R;

    #[track_caller]
    fn with_unwrapped_global<R, F>(self, func: F) -> R
    where
        F: FnOnce(&Self::Key) -> R,
    {
        self.with_global(func).unwrap_display()
    }
}
