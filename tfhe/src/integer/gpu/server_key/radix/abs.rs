use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};
use crate::integer::gpu::{unchecked_signed_abs_radix_kb_assign_async, PBSType};

impl CudaServerKey {
    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub unsafe fn unchecked_abs_assign_async<T>(&self, ct: &mut T, streams: &CudaStreams)
    where
        T: CudaIntegerRadixCiphertext,
    {
        let num_blocks = ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32;

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_signed_abs_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    num_blocks,
                    PBSType::Classical,
                    LweBskGroupingFactor(0),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_signed_abs_radix_kb_assign_async(
                    streams,
                    &mut ct.as_mut().d_blocks.0.d_vec,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    self.key_switching_key
                        .input_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key
                        .output_key_lwe_size()
                        .to_lwe_dimension(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    num_blocks,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                );
            }
        };
    }
    pub fn unchecked_abs<T>(&self, ct: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut res = unsafe { ct.duplicate_async(streams) };
        if T::IS_SIGNED {
            unsafe { self.unchecked_abs_assign_async(&mut res, streams) };
        }
        streams.synchronize();
        res
    }

    /// Computes homomorphically an absolute value of ciphertext encrypting integer
    /// values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(gpu_index);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, num_blocks, &streams);
    ///
    /// let msg = -14i32;
    ///
    /// let ct = cks.encrypt_signed(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
    ///
    /// // Compute homomorphically an absolute value:
    /// let d_ct_res = sks.abs(&d_ct, &streams);
    ///
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i32 = cks.decrypt_signed(&ct_res);
    ///
    /// let abs_msg = if msg < 0 { -msg } else { msg };
    /// assert_eq!(dec_result, abs_msg );
    /// ```
    pub fn abs<T>(&self, ct: &T, streams: &CudaStreams) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        let mut res = unsafe { ct.duplicate_async(streams) };
        if !ct.block_carries_are_empty() {
            unsafe { self.full_propagate_assign_async(&mut res, streams) };
        };
        if T::IS_SIGNED {
            unsafe { self.unchecked_abs_assign_async(&mut res, streams) };
        }
        streams.synchronize();
        res
    }
}
