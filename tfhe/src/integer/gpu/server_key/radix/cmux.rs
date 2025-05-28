use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::integer::gpu::{
    get_cmux_integer_radix_kb_size_on_gpu, get_full_propagate_assign_size_on_gpu,
    unchecked_cmux_integer_radix_kb_async, CudaServerKey, PBSType,
};

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
        stream: &CudaStreams,
    ) -> T {
        let lwe_ciphertext_count = true_ct.as_ref().d_blocks.lwe_ciphertext_count();
        let mut result: T = self
            .create_trivial_zero_radix(true_ct.as_ref().d_blocks.lwe_ciphertext_count().0, stream);

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    unchecked_cmux_integer_radix_kb_async(
                        stream,
                        result.as_mut(),
                        condition,
                        true_ct.as_ref(),
                        false_ct.as_ref(),
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
                        PBSType::Classical,
                        LweBskGroupingFactor(0),
                        d_bsk.d_ms_noise_reduction_key.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    unchecked_cmux_integer_radix_kb_async(
                        stream,
                        result.as_mut(),
                        condition,
                        true_ct.as_ref(),
                        false_ct.as_ref(),
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
                        lwe_ciphertext_count.0 as u32,
                        PBSType::MultiBit,
                        d_multibit_bsk.grouping_factor,
                        None,
                    );
                }
            }
        }
        result
    }

    pub fn unchecked_if_then_else<T: CudaIntegerRadixCiphertext>(
        &self,
        condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        stream: &CudaStreams,
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
        stream: &CudaStreams,
    ) -> T {
        let mut tmp_true_ct;
        let mut tmp_false_ct;

        let true_ct = unsafe {
            if true_ct.block_carries_are_empty() {
                true_ct
            } else {
                tmp_true_ct = true_ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_true_ct, stream);
                &tmp_true_ct
            }
        };

        let false_ct = unsafe {
            if false_ct.block_carries_are_empty() {
                false_ct
            } else {
                tmp_false_ct = false_ct.duplicate_async(stream);
                self.full_propagate_assign_async(&mut tmp_false_ct, stream);
                &tmp_false_ct
            }
        };

        self.unchecked_if_then_else(condition, true_ct, false_ct, stream)
    }
    pub fn get_if_then_else_size_on_gpu<T: CudaIntegerRadixCiphertext>(
        &self,
        _condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        streams: &CudaStreams,
    ) -> u64 {
        assert_eq!(
            true_ct.as_ref().d_blocks.lwe_dimension(),
            false_ct.as_ref().d_blocks.lwe_dimension()
        );
        assert_eq!(
            true_ct.as_ref().d_blocks.lwe_ciphertext_count(),
            false_ct.as_ref().d_blocks.lwe_ciphertext_count()
        );
        let full_prop_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_full_propagate_assign_size_on_gpu(
                streams,
                d_bsk.input_lwe_dimension(),
                d_bsk.glwe_dimension(),
                d_bsk.polynomial_size(),
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count(),
                d_bsk.decomp_base_log(),
                self.message_modulus,
                self.carry_modulus,
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_full_propagate_assign_size_on_gpu(
                    streams,
                    d_multibit_bsk.input_lwe_dimension(),
                    d_multibit_bsk.glwe_dimension(),
                    d_multibit_bsk.polynomial_size(),
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count(),
                    d_multibit_bsk.decomp_base_log(),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        let actual_full_prop_mem = match (
            true_ct.block_carries_are_empty(),
            false_ct.block_carries_are_empty(),
        ) {
            (true, true) => 0,
            (true, false) => self.get_ciphertext_size_on_gpu(true_ct) + full_prop_mem,
            (false, true) => full_prop_mem,
            (false, false) => self.get_ciphertext_size_on_gpu(false_ct) + full_prop_mem,
        };

        let lwe_ciphertext_count = true_ct.as_ref().d_blocks.lwe_ciphertext_count();

        let cmux_mem = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_cmux_integer_radix_kb_size_on_gpu(
                streams,
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
                PBSType::Classical,
                LweBskGroupingFactor(0),
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                get_cmux_integer_radix_kb_size_on_gpu(
                    streams,
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
                    lwe_ciphertext_count.0 as u32,
                    PBSType::MultiBit,
                    d_multibit_bsk.grouping_factor,
                    None,
                )
            }
        };
        actual_full_prop_mem.max(cmux_mem)
    }
}
