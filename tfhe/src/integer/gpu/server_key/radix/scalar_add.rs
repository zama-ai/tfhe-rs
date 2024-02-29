use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::CudaServerKey;
use itertools::Itertools;

impl CudaServerKey {
    /// Computes homomorphically an addition between a scalar and a ciphertext.
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
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_scalar_add(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn unchecked_scalar_add<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_add_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_add_assign_async<T>(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) where
        T: DecomposableInto<u8>,
    {
        if scalar > T::ZERO {
            let bits_in_message = self.message_modulus.0.ilog2();
            let decomposer =
                BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();

            let mut d_decomposed_scalar =
                CudaVec::<u64>::new_async(ct.as_ref().d_blocks.lwe_ciphertext_count().0, stream);
            let scalar64 = decomposer
                .collect_vec()
                .iter()
                .map(|&x| x as u64)
                .take(d_decomposed_scalar.len())
                .collect_vec();
            d_decomposed_scalar.copy_from_cpu_async(scalar64.as_slice(), stream);

            let lwe_dimension = ct.as_ref().d_blocks.lwe_dimension();
            // If the scalar is decomposed using less than the number of blocks our ciphertext
            // has, we just don't touch ciphertext's last blocks
            stream.scalar_addition_integer_radix_assign_async(
                &mut ct.as_mut().d_blocks.0.d_vec,
                &d_decomposed_scalar,
                lwe_dimension,
                scalar64.len() as u32,
                self.message_modulus.0 as u32,
                self.carry_modulus.0 as u32,
            );
        }

        ct.as_mut().info = ct.as_ref().info.after_scalar_add(scalar);
    }

    pub fn unchecked_scalar_add_assign<T>(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) where
        T: DecomposableInto<u8>,
    {
        unsafe {
            self.unchecked_scalar_add_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
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
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.scalar_add(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add<T>(
        &self,
        ct: &CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) -> CudaUnsignedRadixCiphertext
    where
        T: DecomposableInto<u8>,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_add_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_add_assign_async<T>(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) where
        T: DecomposableInto<u8>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        };

        self.unchecked_scalar_add_assign_async(ct, scalar, stream);
        self.full_propagate_assign_async(ct, stream);
    }

    pub fn scalar_add_assign<T>(
        &self,
        ct: &mut CudaUnsignedRadixCiphertext,
        scalar: T,
        stream: &CudaStream,
    ) where
        T: DecomposableInto<u8>,
    {
        unsafe {
            self.scalar_add_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }
}
