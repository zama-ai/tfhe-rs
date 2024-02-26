use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaServerKey;

impl CudaServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.unchecked_small_scalar_mul(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_small_scalar_mul(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_small_scalar_mul_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_small_scalar_mul_assign_async(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) {
        match scalar {
            0 => {
                ct.as_mut().d_blocks.0.d_vec.memset_async(0, stream);
            }
            1 => {
                // Multiplication by one is the identity
            }
            _ => {
                let lwe_dimension = ct.as_ref().d_blocks.lwe_dimension();
                let lwe_ciphertext_count = ct.as_ref().d_blocks.lwe_ciphertext_count();

                stream.small_scalar_mult_integer_radix_assign_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    scalar,
                    lwe_dimension,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }

        ct.as_mut().info = ct.as_ref().info.after_small_scalar_mul(scalar as u8);
    }

    pub fn unchecked_small_scalar_mul_assign(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) {
        unsafe {
            self.unchecked_small_scalar_mul_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let msg = 30;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let d_ct_res = sks.small_scalar_mul(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn small_scalar_mul(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.small_scalar_mul_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn small_scalar_mul_assign_async(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        };

        self.unchecked_small_scalar_mul_assign_async(ct, scalar, stream);
        self.full_propagate_assign_async(ct, stream);
    }

    pub fn small_scalar_mul_assign(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: u64,
        stream: &CudaStream,
    ) {
        unsafe {
            self.small_scalar_mul_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }
}
