use crate::core_crypto::gpu::CudaStream;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::server_key::ScalarMultiplier;
use crate::prelude::CastInto;
use itertools::Itertools;

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
    /// let d_ct_res = sks.unchecked_scalar_mul(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn unchecked_scalar_mul<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStream) -> T
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_mul_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_mul_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if scalar == Scalar::ZERO {
            ct.as_mut().d_blocks.0.d_vec.memset_async(0, stream);
            return;
        }

        if scalar == Scalar::ONE {
            return;
        }

        if scalar.is_power_of_two() {
            // Shifting cost one bivariate PBS so its always faster
            // than multiplying
            self.unchecked_scalar_left_shift_assign_async(ct, scalar.ilog2() as u64, stream);
            return;
        }
        let ciphertext = ct.as_mut();
        let num_blocks = ciphertext.d_blocks.lwe_ciphertext_count().0;
        let msg_bits = self.message_modulus.0.ilog2() as usize;
        let decomposer = BlockDecomposer::with_early_stop_at_zero(scalar, 1).iter_as::<u8>();

        // We don't want to compute shifts if we are not going to use the
        // resulting value
        let mut has_at_least_one_set = vec![0u64; msg_bits];
        for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                has_at_least_one_set[i % msg_bits] = 1;
            }
        }

        let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(scalar, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_scalar_mul_integer_radix_classic_kb_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    decomposed_scalar.as_slice(),
                    has_at_least_one_set.as_slice(),
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_bsk.decomp_base_log,
                    d_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    num_blocks as u32,
                    decomposed_scalar.len() as u32,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_scalar_mul_integer_radix_multibit_kb_async(
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    decomposed_scalar.as_slice(),
                    has_at_least_one_set.as_slice(),
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.decomp_level_count,
                    self.key_switching_key.decomposition_base_log(),
                    self.key_switching_key.decomposition_level_count(),
                    d_multibit_bsk.grouping_factor,
                    num_blocks as u32,
                    decomposed_scalar.len() as u32,
                );
            }
        };

        ct.as_mut().info = ct.as_ref().info.after_scalar_mul();
    }

    pub fn unchecked_scalar_mul_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_mul_assign_async(ct, scalar, stream);
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
    /// let d_ct_res = sks.scalar_mul(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(scalar * msg, clear);
    /// ```
    pub fn scalar_mul<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStream) -> T
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_mul_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_mul_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        };

        self.unchecked_scalar_mul_assign_async(ct, scalar, stream);
    }

    pub fn scalar_mul_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, stream: &CudaStream)
    where
        Scalar: ScalarMultiplier + DecomposableInto<u8> + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_mul_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }
}
