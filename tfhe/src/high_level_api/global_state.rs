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
        cell.as_ref().map(InternalServerKey::device)
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
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(hpu_device) => hpu_device.tag.clone(),
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
        #[allow(irrefutable_let_patterns, reason = "It depends on hardware features")]
        let InternalServerKey::Cpu(cpu_key) = key
        else {
            panic!(
                "Cpu key requested but only the key for {:?} is available",
                key.device()
            )
        };
        func(cpu_key)
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
        let InternalServerKey::Cuda(cuda_key) = key else {
            panic!(
                "CUDA key requested but only the key for {:?} is available",
                key.device()
            )
        };
        func(cuda_key)
    })
}

#[cfg(feature = "gpu")]
pub(in crate::high_level_api) use gpu::with_thread_local_cuda_streams_for_gpu_indexes;

#[cfg(feature = "gpu")]
pub use gpu::CudaGpuChoice;

#[derive(Clone)]
#[cfg(feature = "gpu")]
pub struct CustomMultiGpuIndexes(Vec<GpuIndex>);

#[cfg(feature = "gpu")]
mod gpu {
    use crate::core_crypto::gpu::get_number_of_gpus;

    use super::*;
    use std::cell::LazyCell;

    struct CudaStreamPool {
        custom: Option<CudaStreams>,
        single: Vec<LazyCell<CudaStreams, Box<dyn Fn() -> CudaStreams>>>,
    }

    impl CudaStreamPool {
        fn new() -> Self {
            Self {
                custom: None,
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

        if gpu_indexes.len() == 1 {
            POOL.with_borrow(|pool| func(&pool.single[gpu_indexes[0].get() as usize]))
        } else {
            POOL.with_borrow_mut(|pool| match &pool.custom {
                Some(streams) if streams.gpu_indexes != gpu_indexes => {
                    pool.custom = Some(CudaStreams::new_multi_gpu_with_indexes(gpu_indexes));
                }
                None => {
                    pool.custom = Some(CudaStreams::new_multi_gpu_with_indexes(gpu_indexes));
                }
                _ => {}
            });

            POOL.with_borrow(|pool| func(pool.custom.as_ref().unwrap()))
        }
    }

    impl CustomMultiGpuIndexes {
        pub fn new(indexes: Vec<GpuIndex>) -> Self {
            Self(indexes)
        }
        pub fn gpu_indexes(&self) -> &[GpuIndex] {
            self.0.as_slice()
        }
    }

    #[derive(Clone)]
    pub enum CudaGpuChoice {
        Single(GpuIndex),
        Multi,
        Custom(CustomMultiGpuIndexes),
    }

    impl From<GpuIndex> for CudaGpuChoice {
        fn from(value: GpuIndex) -> Self {
            Self::Single(value)
        }
    }

    impl From<Vec<GpuIndex>> for CustomMultiGpuIndexes {
        fn from(value: Vec<GpuIndex>) -> Self {
            Self(value)
        }
    }

    impl From<CustomMultiGpuIndexes> for CudaGpuChoice {
        fn from(values: CustomMultiGpuIndexes) -> Self {
            Self::Custom(values)
        }
    }

    impl CudaGpuChoice {
        pub(crate) fn build_streams(self) -> CudaStreams {
            match self {
                Self::Single(idx) => CudaStreams::new_single_gpu(idx),
                Self::Multi => CudaStreams::new_multi_gpu(),
                Self::Custom(idxs) => CudaStreams::new_multi_gpu_with_indexes(idxs.gpu_indexes()),
            }
        }
    }

    impl Default for CudaGpuChoice {
        fn default() -> Self {
            Self::Multi
        }
    }
}

#[cfg(feature = "hpu")]
pub(in crate::high_level_api) use hpu::with_thread_local_hpu_device;

#[cfg(feature = "hpu")]
mod hpu {
    use super::*;

    use crate::high_level_api::keys::HpuTaggedDevice;

    use super::INTERNAL_KEYS;

    pub(in crate::high_level_api) fn with_thread_local_hpu_device<F, R>(func: F) -> R
    where
        F: FnOnce(&HpuTaggedDevice) -> R,
    {
        INTERNAL_KEYS.with_borrow(|keys| {
            let Some(InternalServerKey::Hpu(device)) = keys else {
                panic!("Hpu device was requested but it is not available")
            };
            func(device)
        })
    }
}
