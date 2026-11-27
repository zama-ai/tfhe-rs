use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaDynamicKeyswitchingKey;
use crate::integer::gpu::{
    cuda_backend_get_cmux_size_on_gpu, cuda_backend_get_full_propagate_assign_size_on_gpu,
    cuda_backend_unchecked_cmux, CudaServerKey,
};

impl CudaServerKey {
    pub(crate) fn unchecked_if_then_else<T: CudaIntegerRadixCiphertext>(
        &self,
        condition: &CudaBooleanBlock,
        true_ct: &T,
        false_ct: &T,
        stream: &CudaStreams,
    ) -> T {
        let lwe_ciphertext_count = true_ct.as_ref().d_blocks.lwe_ciphertext_count();
        let mut result: T = self
            .create_trivial_zero_radix(true_ct.as_ref().d_blocks.lwe_ciphertext_count().0, stream);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            assert_eq!(
                computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.input_lwe_dimension(),
                "KS key output LWE dimension mismatch with BSK input LWE dimension"
            );
            assert_eq!(
                computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
                self.bootstrapping_key.output_lwe_dimension(),
                "KS key input LWE dimension mismatch with BSK big LWE dimension"
            );
            cuda_backend_unchecked_cmux(
                stream,
                result.as_mut(),
                condition,
                true_ct.as_ref(),
                false_ct.as_ref(),
                &computing_ks_key.d_vec,
                self.message_modulus,
                self.carry_modulus,
                &self.bootstrapping_key,
                computing_ks_key.params_ffi(),
                lwe_ciphertext_count.0 as u32,
            );
        }
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

        let true_ct = if true_ct.block_carries_are_empty() {
            true_ct
        } else {
            tmp_true_ct = true_ct.duplicate(stream);
            self.full_propagate_assign(&mut tmp_true_ct, stream);
            &tmp_true_ct
        };

        let false_ct = if false_ct.block_carries_are_empty() {
            false_ct
        } else {
            tmp_false_ct = false_ct.duplicate(stream);
            self.full_propagate_assign(&mut tmp_false_ct, stream);
            &tmp_false_ct
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
        self.get_if_then_else_size_on_gpu_from_branches(true_ct, false_ct, streams)
    }

    /// [`Self::get_if_then_else_size_on_gpu`] without the condition, which it does not depend
    /// on: lets callers that only hold a radix for the condition avoid building a
    /// `CudaBooleanBlock` (a GPU copy) just to get the estimate.
    pub(crate) fn get_if_then_else_size_on_gpu_from_branches<T: CudaIntegerRadixCiphertext>(
        &self,
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
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        let full_prop_mem = cuda_backend_get_full_propagate_assign_size_on_gpu(
            streams,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            true_ct.as_ref().d_blocks.lwe_ciphertext_count().0 as u32,
            self.message_modulus,
            self.carry_modulus,
        );
        // A dirty branch is duplicated and propagated; both copies stay alive during the cmux
        let true_copy = if true_ct.block_carries_are_empty() {
            0
        } else {
            self.get_ciphertext_size_on_gpu(true_ct)
        };
        let false_copy = if false_ct.block_carries_are_empty() {
            0
        } else {
            self.get_ciphertext_size_on_gpu(false_ct)
        };
        let actual_full_prop_mem = if true_copy + false_copy == 0 {
            0
        } else {
            full_prop_mem
        };
        // unchecked_if_then_else returns a new radix
        let output = self.get_ciphertext_size_on_gpu(true_ct);

        let lwe_ciphertext_count = true_ct.as_ref().d_blocks.lwe_ciphertext_count();

        assert_eq!(
            computing_ks_key.output_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.input_lwe_dimension(),
            "KS key output LWE dimension mismatch with BSK input LWE dimension"
        );
        assert_eq!(
            computing_ks_key.input_key_lwe_size().to_lwe_dimension(),
            self.bootstrapping_key.output_lwe_dimension(),
            "KS key input LWE dimension mismatch with BSK big LWE dimension"
        );
        let cmux_mem = cuda_backend_get_cmux_size_on_gpu(
            streams,
            self.message_modulus,
            self.carry_modulus,
            &self.bootstrapping_key,
            computing_ks_key.params_ffi(),
            lwe_ciphertext_count.0 as u32,
        );
        true_copy + false_copy + actual_full_prop_mem.max(output + cmux_mem)
    }
}
