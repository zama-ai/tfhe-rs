pub mod algorithms;
pub mod entities;
pub mod ffi;
pub mod slice;
pub mod vec;

use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweCiphertextCount,
    GlweDimension, LweCiphertextCount, LweDimension, PolynomialSize, UnsignedInteger,
};
pub use algorithms::*;
pub use entities::*;
pub use ffi::*;
use std::ffi::c_void;
use tfhe_cuda_backend::bindings::*;
use tfhe_cuda_backend::cuda_bind::*;

pub struct CudaStreams {
    pub ptr: Vec<*mut c_void>,
    pub gpu_indexes: Vec<GpuIndex>,
}

#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for CudaStreams {}
unsafe impl Sync for CudaStreams {}

pub enum PBSMSNoiseReductionType {
    NoReduction = PBS_MS_REDUCTION_T_NO_REDUCTION as isize,
    Centered = PBS_MS_REDUCTION_T_CENTERED as isize,
}

impl CudaStreams {
    /// Create a new `CudaStreams` structure with as many GPUs as there are on the machine
    #[cfg(feature = "gpu-debug-fake-multi-gpu")]
    pub fn new_multi_gpu() -> Self {
        let gpu_count = 4;
        assert_eq!(
            gpu_count, 4,
            "The fake multi-gpu debug target can only be used on single GPU machines"
        );

        let mut gpu_indexes = Vec::with_capacity(gpu_count as usize);
        let mut ptr_array = Vec::with_capacity(gpu_count as usize);

        for _ in 0..gpu_count {
            ptr_array.push(unsafe { cuda_create_stream(0) });
            gpu_indexes.push(GpuIndex::new(0));
        }
        Self {
            ptr: ptr_array,
            gpu_indexes,
        }
    }

    #[cfg(not(feature = "gpu-debug-fake-multi-gpu"))]
    pub fn new_multi_gpu() -> Self {
        let gpu_count = get_number_of_gpus();

        let mut gpu_indexes = Vec::with_capacity(gpu_count as usize);
        let mut ptr_array = Vec::with_capacity(gpu_count as usize);

        for i in 0..gpu_count {
            ptr_array.push(unsafe { cuda_create_stream(i) });
            gpu_indexes.push(GpuIndex::new(i));
        }
        Self {
            ptr: ptr_array,
            gpu_indexes,
        }
    }

    /// Create a new `CudaStreams` structure with the GPUs with id provided in a list
    pub fn new_multi_gpu_with_indexes(indexes: &[GpuIndex]) -> Self {
        let gpu_count = get_number_of_gpus();

        let mut gpu_indexes = Vec::with_capacity(indexes.len());
        let mut ptr_array = Vec::with_capacity(indexes.len());

        for &i in indexes {
            let index = i.get();
            assert!(index < gpu_count, "Cuda error: invalid device index");
            ptr_array.push(unsafe { cuda_create_stream(index) });
            gpu_indexes.push(i);
        }
        Self {
            ptr: ptr_array,
            gpu_indexes,
        }
    }
    /// Create a new `CudaStreams` structure with one GPU, whose index corresponds to the one given
    /// as input
    pub fn new_single_gpu(gpu_index: GpuIndex) -> Self {
        Self {
            ptr: vec![unsafe { cuda_create_stream(gpu_index.get()) }],
            gpu_indexes: vec![gpu_index],
        }
    }
    /// Synchronize all cuda streams in the `CudaStreams` structure
    pub fn synchronize(&self) {
        for i in 0..self.len() {
            unsafe {
                cuda_synchronize_stream(self.ptr[i], self.gpu_indexes[i].get());
            }
        }
    }
    /// Synchronize one cuda streams in the `CudaStreams` structure
    pub fn synchronize_one(&self, gpu_index: u32) {
        unsafe {
            cuda_synchronize_stream(
                self.ptr[gpu_index as usize],
                self.gpu_indexes[gpu_index as usize].get(),
            );
        }
    }
    /// Return the number of GPU indexes, which is the same as the number of Cuda streams
    pub fn len(&self) -> usize {
        self.gpu_indexes.len()
    }
    /// Returns `true` if the CudaVec contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn gpu_indexes(&self) -> &[GpuIndex] {
        &self.gpu_indexes
    }

    /// Returns a pointer the array of GpuIndex as u32
    pub(crate) fn gpu_indexes_ptr(&self) -> *const u32 {
        // The cast here is safe as GpuIndex is repr(transparent)
        self.gpu_indexes.as_ptr().cast()
    }

    pub fn ffi(&self) -> CudaStreamsFFI {
        CudaStreamsFFI {
            streams: self.ptr.as_ptr(),
            gpu_indexes: self.gpu_indexes_ptr(),
            gpu_count: self.len() as u32,
        }
    }
}

impl Clone for CudaStreams {
    fn clone(&self) -> Self {
        // The `new_multi_gpu_with_indexes()` function is used here to adapt to any specific type of
        // streams being cloned (single, multi, or custom)
        Self::new_multi_gpu_with_indexes(self.gpu_indexes.as_slice())
    }
}

impl Drop for CudaStreams {
    fn drop(&mut self) {
        for (i, &s) in self.ptr.iter().enumerate() {
            unsafe {
                cuda_destroy_stream(s, self.gpu_indexes[i].get());
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct CudaLweList<T: UnsignedInteger> {
    // Pointer to GPU data
    pub d_vec: CudaVec<T>,
    // Number of ciphertexts in the array
    pub lwe_ciphertext_count: LweCiphertextCount,
    // Lwe dimension
    pub lwe_dimension: LweDimension,
    // Ciphertext Modulus
    pub ciphertext_modulus: CiphertextModulus<T>,
}

impl<T: UnsignedInteger> CudaLweList<T> {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            d_vec: self.d_vec.duplicate(streams),
            lwe_ciphertext_count: self.lwe_ciphertext_count,
            lwe_dimension: self.lwe_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CudaGlweList<T: UnsignedInteger> {
    // Pointer to GPU data
    pub d_vec: CudaVec<T>,
    // Number of ciphertexts in the array
    pub glwe_ciphertext_count: GlweCiphertextCount,
    // Glwe dimension
    pub glwe_dimension: GlweDimension,
    // Polynomial size
    pub polynomial_size: PolynomialSize,
    // Ciphertext Modulus
    pub ciphertext_modulus: CiphertextModulus<T>,
}

impl<T: UnsignedInteger> CudaGlweList<T> {
    pub fn duplicate(&self, streams: &CudaStreams) -> Self {
        Self {
            d_vec: self.d_vec.duplicate(streams),
            glwe_ciphertext_count: self.glwe_ciphertext_count,
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}
/// Get the number of GPUs on the machine
pub fn get_number_of_gpus() -> u32 {
    unsafe { cuda_get_number_of_gpus() as u32 }
}

/// Get the number of sms on the GPU
pub fn get_number_of_sms() -> u32 {
    unsafe { cuda_get_number_of_sms() as u32 }
}

/// Synchronize device
pub fn synchronize_device(gpu_index: u32) {
    unsafe { cuda_synchronize_device(gpu_index) }
}

/// Synchronize all devices
pub fn synchronize_devices(streams: &CudaStreams) {
    for i in 0..streams.gpu_indexes.len() {
        unsafe { cuda_synchronize_device(streams.gpu_indexes.get(i).unwrap().get()) }
    }
}

/// Check there is enough memory on the device to allocate the necessary data
pub fn check_valid_cuda_malloc(size: u64, gpu_index: GpuIndex) -> bool {
    unsafe { cuda_check_valid_malloc(size, gpu_index.get()) }
}

/// Check if a memory allocation fits in GPU memory. If it doesn't fit, panic with
/// a helpful message.
pub fn check_valid_cuda_malloc_assert_oom(size: u64, gpu_index: GpuIndex) {
    if !check_valid_cuda_malloc(size, gpu_index) {
        let total_memory;
        unsafe {
            total_memory = cuda_device_total_memory(gpu_index.get());
        }
        panic!(
            "Not enough memory on GPU {}. Allocating {} bytes exceeds total memory: {} bytes",
            gpu_index.get(),
            size,
            total_memory
        );
    }
}

// Determine if a cuda device is available, at runtime
pub fn is_cuda_available() -> bool {
    let result = unsafe { cuda_is_available() };
    result == 1u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_gpu_info() {
        println!("Number of GPUs: {}", get_number_of_gpus());
    }
    #[test]
    fn allocate_and_copy() {
        let vec = vec![1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let stream = CudaStreams::new_single_gpu(GpuIndex::new(0));
        unsafe {
            let mut d_vec: CudaVec<u64> = CudaVec::<u64>::new_async(vec.len(), &stream, 0);
            d_vec.copy_from_cpu_async(&vec, &stream, 0);
            let mut empty = vec![0_u64; vec.len()];
            d_vec.copy_to_cpu_async(&mut empty, &stream, 0);
            stream.synchronize();
            assert_eq!(vec, empty);
        }
    }
}
