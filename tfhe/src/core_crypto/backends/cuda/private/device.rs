use crate::core_crypto::backends::cuda::engines::CudaError;
use crate::core_crypto::backends::cuda::private::pointers::StreamPointer;
use crate::core_crypto::backends::cuda::private::vec::CudaVec;
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweCiphertextIndex, LweDimension,
    PolynomialSize, SharedMemoryAmount,
};
use concrete_cuda::cuda_bind::*;
use std::ffi::c_void;
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuIndex(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumberOfSamples(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumberOfGpus(pub usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CudaStream {
    gpu_index: GpuIndex,
    stream: StreamPointer,
}

impl CudaStream {
    /// Creates a new stream attached to GPU at gpu_index
    pub(crate) fn new(gpu_index: GpuIndex) -> Result<Self, CudaError> {
        if gpu_index.0 >= unsafe { cuda_get_number_of_gpus() } as usize {
            Err(CudaError::InvalidDeviceIndex(gpu_index))
        } else {
            let stream = StreamPointer(unsafe { cuda_create_stream(gpu_index.0 as u32) });
            Ok(CudaStream { gpu_index, stream })
        }
    }

    /// Gets the GPU index the stream is associated to
    pub(crate) fn gpu_index(&self) -> GpuIndex {
        self.gpu_index
    }

    /// Gets the stream handle
    pub(crate) fn stream_handle(&self) -> StreamPointer {
        self.stream
    }

    /// Check that the GPU has enough global memory
    pub(crate) fn check_device_memory(&self, size: u64) -> Result<(), CudaError> {
        let valid = unsafe { cuda_check_valid_malloc(size, self.gpu_index().0 as u32) };
        match valid {
            0 => Ok(()),
            -1 => Err(CudaError::NotEnoughDeviceMemory(self.gpu_index())),
            -2 => Err(CudaError::InvalidDeviceIndex(self.gpu_index())),
            _ => Err(CudaError::UnspecifiedDeviceError(self.gpu_index())),
        }
    }

    /// Allocates `elements` on the GPU
    pub(crate) fn malloc<T>(&self, elements: u32) -> CudaVec<T>
    where
        T: Numeric,
    {
        let size = elements as u64 * std::mem::size_of::<T>() as u64;
        let ptr = unsafe { cuda_malloc(size, self.gpu_index().0 as u32) };
        CudaVec {
            ptr,
            idx: self.gpu_index.0 as u32,
            len: elements as usize,
            _phantom: PhantomData::default(),
        }
    }

    /// Copies data from slice into GPU pointer
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    /// - [CudaStream::cuda_synchronize_device] __must__ be called after the copy
    /// as soon as synchronization is required
    pub(crate) unsafe fn copy_to_gpu_async<T>(&self, dest: &mut CudaVec<T>, src: &[T])
    where
        T: Numeric,
    {
        let size = (src.len() * std::mem::size_of::<T>()) as u64;
        cuda_memcpy_async_to_gpu(
            dest.as_mut_c_ptr(),
            src.as_ptr() as *const c_void,
            size,
            self.stream_handle().0,
            self.gpu_index().0 as u32,
        );
    }

    /// Copies data from slice into GPU pointer
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    pub(crate) unsafe fn copy_to_gpu<T>(&self, dest: &mut CudaVec<T>, src: &[T])
    where
        T: Numeric,
    {
        self.copy_to_gpu_async(dest, src);
        self.synchronize_device();
    }

    /// Copies data from GPU pointer into slice
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    /// - [CudaStream::cuda_synchronize_device] __must__ be called as soon as synchronization is
    /// required
    pub(crate) unsafe fn copy_to_cpu_async<T>(&self, dest: &mut [T], src: &CudaVec<T>)
    where
        T: Numeric,
    {
        let size = (dest.len() * std::mem::size_of::<T>()) as u64;
        cuda_memcpy_async_to_cpu(
            dest.as_mut_ptr() as *mut c_void,
            src.as_c_ptr(),
            size,
            self.stream_handle().0,
            self.gpu_index().0 as u32,
        );
    }

    /// Copies data from GPU pointer into slice
    ///
    /// # Safety
    ///
    /// - `dest` __must__ be a valid pointer
    /// - [CudaStream::cuda_synchronize_device] __must__ have been called before
    pub(crate) unsafe fn copy_to_cpu<T>(&self, dest: &mut [T], src: &CudaVec<T>)
    where
        T: Numeric,
    {
        self.copy_to_cpu_async(dest, src);
        self.synchronize_device();
    }

    /// Synchronizes the device
    #[allow(dead_code)]
    pub(crate) fn synchronize_device(&self) {
        unsafe { cuda_synchronize_device(self.gpu_index().0 as u32) };
    }

    /// Get the maximum amount of shared memory
    pub(crate) fn get_max_shared_memory(&self) -> Result<i32, CudaError> {
        let max_shared_memory = unsafe { cuda_get_max_shared_memory(self.gpu_index().0 as u32) };
        match max_shared_memory {
            0 => Err(CudaError::SharedMemoryNotFound(self.gpu_index())),
            -2 => Err(CudaError::InvalidDeviceIndex(self.gpu_index())),
            _ => Ok(max_shared_memory),
        }
    }

    /// Initialize twiddles
    #[allow(dead_code)]
    pub fn initialize_twiddles(&self, polynomial_size: PolynomialSize) {
        unsafe { cuda_initialize_twiddles(polynomial_size.0 as u32, self.gpu_index.0 as u32) };
    }

    /// Convert bootstrap key
    #[allow(dead_code)]
    pub unsafe fn convert_lwe_bootstrap_key<T: UnsignedInteger>(
        &self,
        dest: &mut CudaVec<f64>,
        src: &[T],
        input_lwe_dim: LweDimension,
        glwe_dim: GlweDimension,
        l_gadget: DecompositionLevelCount,
        polynomial_size: PolynomialSize,
    ) {
        if T::BITS == 32 {
            cuda_convert_lwe_bootstrap_key_32(
                dest.as_mut_c_ptr(),
                src.as_ptr() as *mut c_void,
                self.stream.0,
                self.gpu_index.0 as u32,
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
            )
        } else if T::BITS == 64 {
            cuda_convert_lwe_bootstrap_key_64(
                dest.as_mut_c_ptr(),
                src.as_ptr() as *mut c_void,
                self.stream.0,
                self.gpu_index.0 as u32,
                input_lwe_dim.0 as u32,
                glwe_dim.0 as u32,
                l_gadget.0 as u32,
                polynomial_size.0 as u32,
            )
        }
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_amortized_lwe_ciphertext_vector<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        test_vector: &CudaVec<T>,
        test_vector_indexes: &CudaVec<u32>,
        lwe_array_in: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        num_samples: NumberOfSamples,
        lwe_idx: LweCiphertextIndex,
        max_shared_memory: SharedMemoryAmount,
    ) {
        if T::BITS == 32 {
            cuda_bootstrap_amortized_lwe_ciphertext_vector_32(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                test_vector.as_c_ptr(),
                test_vector_indexes.as_c_ptr(),
                lwe_array_in.as_c_ptr(),
                bootstrapping_key.as_c_ptr(),
                lwe_dimension.0 as u32,
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                num_samples.0 as u32,
                num_samples.0 as u32,
                lwe_idx.0 as u32,
                max_shared_memory.0 as u32,
            )
        } else if T::BITS == 64 {
            cuda_bootstrap_amortized_lwe_ciphertext_vector_64(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                test_vector.as_c_ptr(),
                test_vector_indexes.as_c_ptr(),
                lwe_array_in.as_c_ptr(),
                bootstrapping_key.as_c_ptr(),
                lwe_dimension.0 as u32,
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                num_samples.0 as u32,
                num_samples.0 as u32,
                lwe_idx.0 as u32,
                max_shared_memory.0 as u32,
            )
        }
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_bootstrap_low_latency_lwe_ciphertext_vector<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        test_vector: &CudaVec<T>,
        test_vector_indexes: &CudaVec<u32>,
        lwe_array_in: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        num_samples: NumberOfSamples,
        lwe_idx: LweCiphertextIndex,
        max_shared_memory: SharedMemoryAmount,
    ) {
        if T::BITS == 32 {
            cuda_bootstrap_low_latency_lwe_ciphertext_vector_32(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                test_vector.as_c_ptr(),
                test_vector_indexes.as_c_ptr(),
                lwe_array_in.as_c_ptr(),
                bootstrapping_key.as_c_ptr(),
                lwe_dimension.0 as u32,
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                num_samples.0 as u32,
                num_samples.0 as u32,
                lwe_idx.0 as u32,
                max_shared_memory.0 as u32,
            )
        } else if T::BITS == 64 {
            cuda_bootstrap_low_latency_lwe_ciphertext_vector_64(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                test_vector.as_c_ptr(),
                test_vector_indexes.as_c_ptr(),
                lwe_array_in.as_c_ptr(),
                bootstrapping_key.as_c_ptr(),
                lwe_dimension.0 as u32,
                glwe_dimension.0 as u32,
                polynomial_size.0 as u32,
                base_log.0 as u32,
                level.0 as u32,
                num_samples.0 as u32,
                num_samples.0 as u32,
                lwe_idx.0 as u32,
                max_shared_memory.0 as u32,
            )
        }
    }

    /// Discarding keyswitch on a vector of LWE ciphertexts
    #[allow(dead_code, clippy::too_many_arguments)]
    pub unsafe fn discard_keyswitch_lwe_ciphertext_vector<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        keyswitch_key: &CudaVec<T>,
        base_log: DecompositionBaseLog,
        l_gadget: DecompositionLevelCount,
        num_samples: NumberOfSamples,
    ) {
        if T::BITS == 32 {
            cuda_keyswitch_lwe_ciphertext_vector_32(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                lwe_array_in.as_c_ptr(),
                keyswitch_key.as_c_ptr(),
                input_lwe_dimension.0 as u32,
                output_lwe_dimension.0 as u32,
                base_log.0 as u32,
                l_gadget.0 as u32,
                num_samples.0 as u32,
            )
        } else if T::BITS == 64 {
            cuda_keyswitch_lwe_ciphertext_vector_64(
                self.stream.0,
                lwe_array_out.as_mut_c_ptr(),
                lwe_array_in.as_c_ptr(),
                keyswitch_key.as_c_ptr(),
                input_lwe_dimension.0 as u32,
                output_lwe_dimension.0 as u32,
                base_log.0 as u32,
                l_gadget.0 as u32,
                num_samples.0 as u32,
            )
        }
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        unsafe {
            cuda_destroy_stream(self.stream_handle().0, self.gpu_index().0 as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_gpu_info() {
        println!("Number of GPUs: {}", unsafe { cuda_get_number_of_gpus() });
        let gpu_index = GpuIndex(0);
        let stream = CudaStream::new(gpu_index).unwrap();
        println!(
            "Max shared memory: {}",
            stream.get_max_shared_memory().unwrap()
        )
    }
    #[test]
    fn allocate_and_copy() {
        let vec = vec![1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let gpu_index = GpuIndex(0);
        let stream = CudaStream::new(gpu_index).unwrap();
        stream.check_device_memory(vec.len() as u64).unwrap();
        let mut d_vec: CudaVec<u64> = stream.malloc::<u64>(vec.len() as u32);
        unsafe {
            stream.copy_to_gpu(&mut d_vec, &vec);
        }
        let mut empty = vec![0_u64; vec.len()];
        unsafe {
            stream.copy_to_cpu(&mut empty, &d_vec);
        }
        assert_eq!(vec, empty);
    }
}
