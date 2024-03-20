pub mod algorithms;
pub mod entities;
pub mod vec;

use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, GlweCiphertextCount,
    GlweDimension, LweBskGroupingFactor, LweCiphertextCount, LweCiphertextIndex, LweDimension,
    PolynomialSize, UnsignedInteger,
};
pub use algorithms::*;
pub use entities::*;
use std::ffi::c_void;
use tfhe_cuda_backend::cuda_bind::*;

#[derive(Debug, Clone)]
pub struct CudaPtr {
    ptr: *mut c_void,
    device: CudaDevice,
}

#[derive(Debug, Clone)]
pub struct CudaStream {
    ptr: *mut c_void,
    device: CudaDevice,
}

impl CudaStream {
    pub fn new_unchecked(device: CudaDevice) -> Self {
        let gpu_index = device.gpu_index();
        unsafe {
            let ptr = cuda_create_stream(gpu_index);

            Self { ptr, device }
        }
    }

    /// # Safety
    ///
    /// - `stream` __must__ be a valid pointer
    pub unsafe fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr
    }

    /// # Safety
    ///
    /// - `stream` __must__ be a valid pointer
    pub unsafe fn as_c_ptr(&self) -> *const c_void {
        self.ptr.cast_const()
    }

    pub fn device(&self) -> CudaDevice {
        self.device
    }

    /// Synchronizes the stream
    pub fn synchronize(&self) {
        unsafe { cuda_synchronize_stream(self.as_c_ptr()) };
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bootstrap_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_out_indexes: &CudaVec<T>,
        test_vector: &CudaVec<T>,
        test_vector_indexes: &CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        lwe_in_indexes: &CudaVec<T>,
        bootstrapping_key: &CudaVec<f64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        num_samples: u32,
        lwe_idx: LweCiphertextIndex,
    ) {
        let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
        scratch_cuda_programmable_bootstrap_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(pbs_buffer),
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            num_samples,
            self.device().get_max_shared_memory() as u32,
            true,
        );
        cuda_programmable_bootstrap_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_out_indexes.as_c_ptr(),
            test_vector.as_c_ptr(),
            test_vector_indexes.as_c_ptr(),
            lwe_array_in.as_c_ptr(),
            lwe_in_indexes.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            pbs_buffer,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            base_log.0 as u32,
            level.0 as u32,
            num_samples,
            num_samples,
            lwe_idx.0 as u32,
            self.device().get_max_shared_memory() as u32,
        );
        cleanup_cuda_programmable_bootstrap(self.as_c_ptr(), std::ptr::addr_of_mut!(pbs_buffer));
    }

    /// Discarding bootstrap on a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn programmable_bootstrap_multi_bit_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        output_indexes: &CudaVec<T>,
        test_vector: &CudaVec<T>,
        test_vector_indexes: &CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        input_indexes: &CudaVec<T>,
        bootstrapping_key: &CudaVec<u64>,
        lwe_dimension: LweDimension,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        num_samples: u32,
        lwe_idx: LweCiphertextIndex,
    ) {
        let mut pbs_buffer: *mut i8 = std::ptr::null_mut();
        scratch_cuda_multi_bit_programmable_bootstrap_64(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(pbs_buffer),
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            level.0 as u32,
            grouping_factor.0 as u32,
            num_samples,
            self.device().get_max_shared_memory() as u32,
            true,
            0u32,
        );
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            output_indexes.as_c_ptr(),
            test_vector.as_c_ptr(),
            test_vector_indexes.as_c_ptr(),
            lwe_array_in.as_c_ptr(),
            input_indexes.as_c_ptr(),
            bootstrapping_key.as_c_ptr(),
            pbs_buffer,
            lwe_dimension.0 as u32,
            glwe_dimension.0 as u32,
            polynomial_size.0 as u32,
            grouping_factor.0 as u32,
            base_log.0 as u32,
            level.0 as u32,
            num_samples,
            num_samples,
            lwe_idx.0 as u32,
            self.device().get_max_shared_memory() as u32,
            0u32,
        );
        cleanup_cuda_multi_bit_programmable_bootstrap(
            self.as_c_ptr(),
            std::ptr::addr_of_mut!(pbs_buffer),
        );
    }

    /// Discarding keyswitch on a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn keyswitch_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_out_indexes: &CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        lwe_in_indexes: &CudaVec<T>,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        keyswitch_key: &CudaVec<T>,
        base_log: DecompositionBaseLog,
        l_gadget: DecompositionLevelCount,
        num_samples: u32,
    ) {
        cuda_keyswitch_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_out_indexes.as_c_ptr(),
            lwe_array_in.as_c_ptr(),
            lwe_in_indexes.as_c_ptr(),
            keyswitch_key.as_c_ptr(),
            input_lwe_dimension.0 as u32,
            output_lwe_dimension.0 as u32,
            base_log.0 as u32,
            l_gadget.0 as u32,
            num_samples,
        );
    }

    /// Convert keyswitch key
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn convert_lwe_keyswitch_key_async<T: UnsignedInteger>(
        &self,
        dest: &mut CudaVec<T>,
        src: &[T],
    ) {
        dest.copy_from_cpu_async(src, self);
    }

    /// Convert programmable bootstrap key
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn convert_lwe_programmable_bootstrap_key_async<T: UnsignedInteger>(
        &self,
        dest: &mut CudaVec<f64>,
        src: &[T],
        input_lwe_dim: LweDimension,
        glwe_dim: GlweDimension,
        l_gadget: DecompositionLevelCount,
        polynomial_size: PolynomialSize,
    ) {
        let size = std::mem::size_of_val(src);
        assert_eq!(dest.len() * std::mem::size_of::<T>(), size);

        cuda_convert_lwe_programmable_bootstrap_key_64(
            dest.as_mut_c_ptr(),
            src.as_ptr().cast(),
            self.as_c_ptr(),
            input_lwe_dim.0 as u32,
            glwe_dim.0 as u32,
            l_gadget.0 as u32,
            polynomial_size.0 as u32,
        );
    }

    /// Convert multi-bit programmable bootstrap key
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn convert_lwe_multi_bit_programmable_bootstrap_key_async<T: UnsignedInteger>(
        &self,
        dest: &mut CudaVec<u64>,
        src: &[T],
        input_lwe_dim: LweDimension,
        glwe_dim: GlweDimension,
        l_gadget: DecompositionLevelCount,
        polynomial_size: PolynomialSize,
        grouping_factor: LweBskGroupingFactor,
    ) {
        let size = std::mem::size_of_val(src);
        assert_eq!(dest.len() * std::mem::size_of::<T>(), size);
        cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
            dest.as_mut_c_ptr(),
            src.as_ptr().cast(),
            self.as_c_ptr(),
            input_lwe_dim.0 as u32,
            glwe_dim.0 as u32,
            l_gadget.0 as u32,
            polynomial_size.0 as u32,
            grouping_factor.0 as u32,
        )
    }

    /// Discarding addition of a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn add_lwe_ciphertext_vector_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in_1: &CudaVec<T>,
        lwe_array_in_2: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_add_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_in_1.as_c_ptr(),
            lwe_array_in_2.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Discarding assigned addition of a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn add_lwe_ciphertext_vector_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_add_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_out.as_c_ptr(),
            lwe_array_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Discarding addition of a vector of LWE ciphertexts with a vector of plaintexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn add_lwe_ciphertext_vector_plaintext_vector_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        plaintext_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_in.as_c_ptr(),
            plaintext_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Discarding assigned addition of a vector of LWE ciphertexts with a vector of plaintexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn add_lwe_ciphertext_vector_plaintext_vector_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        plaintext_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_add_lwe_ciphertext_vector_plaintext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_out.as_c_ptr(),
            plaintext_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Discarding negation of a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn negate_lwe_ciphertext_vector_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_negate_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Discarding assigned negation of a vector of LWE ciphertexts
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn negate_lwe_ciphertext_vector_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_negate_lwe_ciphertext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_out.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    #[allow(clippy::too_many_arguments)]
    /// Discarding assign negation of a vector of LWE ciphertexts representing an integer
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn negate_integer_radix_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array: &mut CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
        message_modulus: u32,
        carry_modulus: u32,
    ) {
        cuda_negate_integer_radix_ciphertext_64_inplace(
            self.as_c_ptr(),
            lwe_array.as_mut_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
            message_modulus,
            carry_modulus,
        );
    }

    /// Multiplication of a vector of LWEs with a vector of cleartexts (assigned)
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn mult_lwe_ciphertext_vector_cleartext_vector_assign_async<T: UnsignedInteger>(
        &self,
        lwe_array: &mut CudaVec<T>,
        cleartext_array_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
            self.as_c_ptr(),
            lwe_array.as_mut_c_ptr(),
            lwe_array.as_c_ptr(),
            cleartext_array_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }

    /// Multiplication of a vector of LWEs with a vector of cleartexts.
    ///
    /// # Safety
    ///
    /// [CudaStream::synchronize] __must__ be called as soon as synchronization is
    /// required
    pub unsafe fn mult_lwe_ciphertext_vector_cleartext_vector<T: UnsignedInteger>(
        &self,
        lwe_array_out: &mut CudaVec<T>,
        lwe_array_in: &CudaVec<T>,
        cleartext_array_in: &CudaVec<T>,
        lwe_dimension: LweDimension,
        num_samples: u32,
    ) {
        cuda_mult_lwe_ciphertext_vector_cleartext_vector_64(
            self.as_c_ptr(),
            lwe_array_out.as_mut_c_ptr(),
            lwe_array_in.as_c_ptr(),
            cleartext_array_in.as_c_ptr(),
            lwe_dimension.0 as u32,
            num_samples,
        );
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        self.synchronize();
        unsafe {
            cuda_destroy_stream(self.as_mut_c_ptr());
        }
    }
}

impl CudaPtr {
    /// Returns a raw pointer to the vector’s buffer.
    pub fn as_c_ptr(&self) -> *const c_void {
        self.ptr.cast_const()
    }

    /// Returns an unsafe mutable pointer to the vector’s buffer.
    pub fn as_mut_c_ptr(&mut self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for CudaPtr {
    /// Free memory for pointer `ptr` synchronously
    fn drop(&mut self) {
        // Synchronizes the device to be sure no stream is still using this pointer
        let device = self.device;
        device.synchronize_device();

        unsafe { cuda_drop(self.as_mut_c_ptr(), device.gpu_index()) };
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CudaDevice {
    gpu_index: u32,
}

impl CudaDevice {
    /// Creates a CudaDevice related to the GPU with index gpu_index
    pub fn new(gpu_index: u32) -> Self {
        Self { gpu_index }
    }

    pub fn gpu_index(&self) -> u32 {
        self.gpu_index
    }

    /// Synchronizes the device
    #[allow(dead_code)]
    pub fn synchronize_device(&self) {
        unsafe { cuda_synchronize_device(self.gpu_index()) };
    }

    /// Get the maximum amount of shared memory
    pub fn get_max_shared_memory(&self) -> i32 {
        unsafe { cuda_get_max_shared_memory(self.gpu_index()) }
    }

    /// Synchronizes the stream
    pub fn get_number_of_gpus(&self) -> i32 {
        unsafe { cuda_get_number_of_gpus() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_gpu_info() {
        println!("Number of GPUs: {}", unsafe { cuda_get_number_of_gpus() });
        let gpu_index: u32 = 0;
        let device = CudaDevice::new(gpu_index);
        println!("Max shared memory: {}", device.get_max_shared_memory())
    }
    #[test]
    fn allocate_and_copy() {
        let vec = vec![1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let gpu_index: u32 = 0;
        let device = CudaDevice::new(gpu_index);
        let stream = CudaStream::new_unchecked(device);
        unsafe {
            let mut d_vec: CudaVec<u64> = CudaVec::<u64>::new_async(vec.len(), &stream);
            d_vec.copy_from_cpu_async(&vec, &stream);
            let mut empty = vec![0_u64; vec.len()];
            d_vec.copy_to_cpu_async(&mut empty, &stream);
            stream.synchronize();
            assert_eq!(vec, empty);
        }
    }
}
