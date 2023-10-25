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
    static INTERNAL_KEYS: RefCell<Option<ServerKey>> = RefCell::new(None);
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
/// # let config = tfhe::ConfigBuilder::default().build();
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
/// # let config = tfhe::ConfigBuilder::default().build();
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
    INTERNAL_KEYS.with(|internal_keys| internal_keys.replace_with(|_old| Some(keys)));
}

pub fn unset_server_key() -> Option<ServerKey> {
    INTERNAL_KEYS.with(|internal_keys| internal_keys.replace_with(|_old| None))
}

pub fn with_server_key_as_context<T, F>(keys: ServerKey, f: F) -> (T, ServerKey)
where
    F: FnOnce() -> T,
{
    set_server_key(keys);
    let result = f();
    let keys = unset_server_key();
    (result, keys.unwrap()) // unwrap is ok since we know we did set_server_key
}

/// Convenience function that allows to write functions that needs to access the internal keys.
#[inline]
pub(crate) fn with_internal_keys<T, F>(func: F) -> T
where
    F: FnOnce(&ServerKey) -> T,
{
    // Should use `with_borrow` when its stabilized
    INTERNAL_KEYS.with(|keys| {
        let maybe_key = &*keys.borrow();
        let key = maybe_key
            .as_ref()
            .ok_or(UninitializedServerKey)
            .unwrap_display();
        func(key)
    })
}

/// Global key access trait
pub trait WithGlobalKey: Sized {
    type Key;

    fn with_unwrapped_global<R, F>(self, func: F) -> R
    where
        F: FnOnce(&Self::Key) -> R;
}
