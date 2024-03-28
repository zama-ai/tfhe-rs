use crate::core_crypto::gpu::CudaStream;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::CudaServerKey;

impl CudaServerKey {
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_if_then_else_async<T: CudaIntegerRadixCiphertext>(
        &self,
        condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        stream: &CudaStream,
    ) -> T {
        let lwe_ciphertext_count = true_ct.as_ref().d_blocks.lwe_ciphertext_count();
        let mut result: T = self
            .create_trivial_zero_radix(true_ct.as_ref().d_blocks.lwe_ciphertext_count().0, stream);

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                stream.unchecked_cmux_integer_radix_classic_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &condition.as_ref().ciphertext.d_blocks.0.d_vec,
                    &true_ct.as_ref().d_blocks.0.d_vec,
                    &false_ct.as_ref().d_blocks.0.d_vec,
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
                    lwe_ciphertext_count.0 as u32,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                stream.unchecked_cmux_integer_radix_multibit_kb_async(
                    &mut result.as_mut().d_blocks.0.d_vec,
                    &condition.as_ref().ciphertext.d_blocks.0.d_vec,
                    &true_ct.as_ref().d_blocks.0.d_vec,
                    &false_ct.as_ref().d_blocks.0.d_vec,
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
                    d_multibit_bsk.grouping_factor,
                    lwe_ciphertext_count.0 as u32,
                );
            }
        }

        result
    }
    pub fn unchecked_if_then_else<T: CudaIntegerRadixCiphertext>(
        &self,
        condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        stream: &CudaStream,
    ) -> T {
        let result =
            unsafe { self.unchecked_if_then_else_async(condition, true_ct, false_ct, stream) };
        stream.synchronize();
        result
    }

    pub fn if_then_else<T: CudaIntegerRadixCiphertext>(
        &self,
        condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        stream: &CudaStream,
    ) -> T {
        let mut tmp_true_ct;
        let mut tmp_false_ct;

        let result = unsafe {
            let true_ct = if true_ct.block_carries_are_empty() {
                true_ct
            } else {
                tmp_true_ct = true_ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_true_ct, stream);
                &tmp_true_ct
            };

            let false_ct = if false_ct.block_carries_are_empty() {
                false_ct
            } else {
                tmp_false_ct = false_ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_false_ct, stream);
                &tmp_false_ct
            };

            self.unchecked_if_then_else_async(condition, true_ct, false_ct, stream)
        };
        stream.synchronize();
        result
    }
}
