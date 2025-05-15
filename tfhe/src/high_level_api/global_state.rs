//! In this module, we store the hidden (to the end-user) internal state/keys that are needed to
//! perform operations.
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::vec::GpuIndex;
#[cfg(feature = "gpu")]
use crate::core_crypto::gpu::CudaStreams;
use crate::high_level_api::errors::{UninitializedServerKey, UnwrapResultExt};
use crate::high_level_api::keys::{InternalServerKey, ServerKey};
#[cfg(feature = "gpu")]
use crate::high_level_api::CudaServerKey;
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
    let _old = replace_server_key(Some(keys));
}

pub fn unset_server_key() {
    let _old = INTERNAL_KEYS.take();
}

fn replace_server_key(new_one: Option<impl Into<InternalServerKey>>) -> Option<InternalServerKey> {
    let keys = new_one.map(Into::into);
    #[cfg(feature = "gpu")]
    if let Some(InternalServerKey::Cuda(cuda_key)) = &keys {
        gpu::CUDA_STREAMS.with_borrow_mut(|current_streams| {
            if current_streams.gpu_indexes() != cuda_key.gpu_indexes() {
                *current_streams = cuda_key.build_streams();
            }
        });
    }
    INTERNAL_KEYS.replace(keys)
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

#[inline]
#[cfg(feature = "gpu")]
pub(crate) fn with_cuda_internal_keys<T, F>(func: F) -> T
where
    F: FnOnce(&CudaServerKey) -> T,
{
    // Should use `with_borrow` when its stabilized
    INTERNAL_KEYS.with(|keys| {
        let maybe_key = &*keys.borrow();
        let key = maybe_key
            .as_ref()
            .ok_or(UninitializedServerKey)
            .unwrap_display();
        match key {
            InternalServerKey::Cuda(key) => func(key),
            InternalServerKey::Cpu(_) => {
                panic!("Cuda key requested but only cpu key is available")
            }
        }
    })
}

#[cfg(feature = "gpu")]
pub(in crate::high_level_api) use gpu::{
    with_thread_local_cuda_streams, with_thread_local_cuda_streams_for_gpu_indexes,
};

#[cfg(feature = "gpu")]
pub use gpu::CudaGpuChoice;

#[cfg(feature = "gpu")]
mod gpu {
    use crate::core_crypto::gpu::get_number_of_gpus;

    use super::*;
    use std::cell::LazyCell;

    thread_local! {
        pub(crate) static CUDA_STREAMS: RefCell<CudaStreams> = RefCell::new(CudaStreams::new_multi_gpu());
    }

    pub(in crate::high_level_api) fn with_thread_local_cuda_streams<
        R,
        F: for<'a> FnOnce(&'a CudaStreams) -> R,
    >(
        func: F,
    ) -> R {
        CUDA_STREAMS.with(|cell| func(&cell.borrow()))
    }

    struct CudaStreamPool {
        multi: LazyCell<CudaStreams>,
        single: Vec<LazyCell<CudaStreams, Box<dyn Fn() -> CudaStreams>>>,
    }

    impl CudaStreamPool {
        fn new() -> Self {
            Self {
                multi: LazyCell::new(CudaStreams::new_multi_gpu),
                single: (0..get_number_of_gpus())
                    .map(|index| {
                        let ctor =
                            Box::new(move || CudaStreams::new_single_gpu(GpuIndex::new(index)));
                        LazyCell::new(ctor as Box<dyn Fn() -> CudaStreams>)
                    })
                    .collect(),
            }
        }
    }

    impl<'a> std::ops::Index<&'a [GpuIndex]> for CudaStreamPool {
        type Output = CudaStreams;

        fn index(&self, indexes: &'a [GpuIndex]) -> &Self::Output {
            match indexes.len() {
                0 => panic!("Internal error: Gpu indexes must not be empty"),
                1 => &self.single[indexes[0].get() as usize],
                _ => &self.multi,
            }
        }
    }

    impl std::ops::Index<CudaGpuChoice> for CudaStreamPool {
        type Output = CudaStreams;

        fn index(&self, choice: CudaGpuChoice) -> &Self::Output {
            match choice {
                CudaGpuChoice::Multi => &self.multi,
                CudaGpuChoice::Single(index) => &self.single[index.get() as usize],
            }
        }
    }

    pub(in crate::high_level_api) fn with_thread_local_cuda_streams_for_gpu_indexes<
        R,
        F: for<'a> FnOnce(&'a CudaStreams) -> R,
    >(
        gpu_indexes: &[GpuIndex],
        func: F,
    ) -> R {
        thread_local! {
            static POOL: RefCell<CudaStreamPool> = RefCell::new(CudaStreamPool::new());
        }
        POOL.with_borrow(|stream_pool| {
            let stream = &stream_pool[gpu_indexes];
            func(stream)
        })
    }
    #[derive(Copy, Clone)]
    pub enum CudaGpuChoice {
        Single(GpuIndex),
        Multi,
    }

    impl From<GpuIndex> for CudaGpuChoice {
        fn from(value: GpuIndex) -> Self {
            Self::Single(value)
        }
    }

    impl CudaGpuChoice {
        pub(in crate::high_level_api) fn build_streams(self) -> CudaStreams {
            match self {
                Self::Single(idx) => CudaStreams::new_single_gpu(idx),
                Self::Multi => CudaStreams::new_multi_gpu(),
            }
        }
    }

    impl Default for CudaGpuChoice {
        fn default() -> Self {
            Self::Multi
        }
    }
}
