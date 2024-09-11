//! In this module, we store the hidden (to the end-user) internal state/keys that are needed to
//! perform operations.
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::errors::{UninitializedServerKey, UnwrapResultExt};
use crate::high_level_api::keys::{InternalServerKey, ServerKey};
use std::cell::RefCell;
/// We store the internal keys as thread local, meaning each thread has its own set of keys.
///
/// This means that the user can do computations in multiple threads
/// (eg a web server that processes multiple requests in multiple threads).
/// The user however, has to initialize the internal keys each time it starts a thread.
thread_local! {
    static INTERNAL_KEYS: RefCell<Option<InternalServerKey>> = const { RefCell::new(None) };
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
/// ```rust
/// use tfhe::{generate_keys, ConfigBuilder};
///
/// let config = ConfigBuilder::default().build();
/// let (client_key, server_key) = generate_keys(config);
///
/// tfhe::set_server_key(server_key);
/// // Now we can do operations on homomorphic types
/// ```
///
///
/// Working with multiple threads
///
/// ```rust
/// use std::thread;
/// use tfhe::ConfigBuilder;
///
/// let config = ConfigBuilder::default().build();
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
/// th2.join().unwrap();
/// th1.join().unwrap();
/// ```
pub fn set_server_key<T: Into<InternalServerKey>>(keys: T) {
    INTERNAL_KEYS.with(|internal_keys| internal_keys.replace_with(|_old| Some(keys.into())));
}

pub fn unset_server_key() {
    INTERNAL_KEYS.with(|internal_keys| {
        let _ = internal_keys.replace_with(|_old| None);
    })
}

pub fn with_server_key_as_context<T, F>(keys: ServerKey, f: F) -> T
where
    F: FnOnce() -> T,
{
    set_server_key(keys);
    let result = f();
    unset_server_key();
    result
}

/// Convenience function that allows to write functions that needs to access the internal keys
///
/// # Panics
///
/// Panics if the server key is not set
#[track_caller]
#[inline]
pub(in crate::high_level_api) fn with_internal_keys<T, F>(func: F) -> T
where
    F: FnOnce(&InternalServerKey) -> T,
{
    try_with_internal_keys(|maybe_key| {
        let key = maybe_key.ok_or(UninitializedServerKey).unwrap_display();
        func(key)
    })
}

#[inline]
pub(in crate::high_level_api) fn try_with_internal_keys<T, F>(func: F) -> T
where
    F: FnOnce(Option<&InternalServerKey>) -> T,
{
    // Should use `with_borrow` when its stabilized
    INTERNAL_KEYS.with(|keys| {
        let maybe_key = &*keys.borrow();
        let key = maybe_key.as_ref();
        func(key)
    })
}

#[inline]
pub(in crate::high_level_api) fn device_of_internal_keys() -> Option<crate::Device> {
    // Should use `with_borrow` when its stabilized
    INTERNAL_KEYS.with(|keys| {
        let cell = keys.borrow();
        Some(match cell.as_ref()? {
            InternalServerKey::Cpu(_) => crate::Device::Cpu,
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => crate::Device::CudaGpu,
        })
    })
}

/// This returns the [tag](crate::Tag) stored in the internal server key
#[inline]
pub(in crate::high_level_api) fn tag_of_internal_server_key() -> crate::Result<crate::Tag> {
    INTERNAL_KEYS.with(|keys| {
        let cell = keys.borrow();
        Ok(match cell.as_ref().ok_or(UninitializedServerKey)? {
            InternalServerKey::Cpu(cpu_key) => cpu_key.tag.clone(),
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => cuda_key.tag.clone(),
        })
    })
}

#[inline]
pub(crate) fn with_cpu_internal_keys<T, F>(func: F) -> T
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
        match key {
            InternalServerKey::Cpu(key) => func(key),
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cpu key requested but only cuda key is available")
            }
        }
    })
}

#[cfg(feature = "gpu")]
thread_local! {
    static CUDA_STREAMS: std::cell::OnceCell<CudaStreams> = std::cell::OnceCell::from(CudaStreams::new_multi_gpu());
}

#[cfg(feature = "gpu")]
pub(in crate::high_level_api) fn with_thread_local_cuda_streams<
    R,
    F: for<'a> FnOnce(&'a CudaStreams) -> R,
>(
    func: F,
) -> R {
    CUDA_STREAMS.with(|cell| func(cell.get().unwrap()))
}
