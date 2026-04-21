use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::cuda_backend_trivium_generate_keystream;
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};

impl CudaServerKey {
    /// Generates a Trivium keystream homomorphically on the GPU.
    ///
    /// # Arguments
    /// * `key` - The encrypted secret key.
    /// * `iv` - The encrypted initialization vector.
    /// * `num_steps` - The number of keystream bits to generate per input.
    /// * `streams` - The CUDA streams to use for execution.
    pub fn trivium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext> {
        let num_key_bits = 80;
        let num_iv_bits = 80;
        let batch_size = 64;

        if key.as_ref().d_blocks.lwe_ciphertext_count().0 != num_key_bits {
            return Err(format!(
                "Input key must contain {} encrypted bits, but contains {}",
                num_key_bits,
                key.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if iv.as_ref().d_blocks.lwe_ciphertext_count().0 != num_iv_bits {
            return Err(format!(
                "Input IV must contain {} encrypted bits, but contains {}",
                num_iv_bits,
                iv.as_ref().d_blocks.lwe_ciphertext_count().0
            )
            .into());
        }

        if !num_steps.is_multiple_of(batch_size) {
            return Err(format!(
                "The number of steps must be a multiple of {batch_size}, but is {num_steps}"
            )
            .into());
        }

        let num_output_bits = num_steps;
        let mut keystream: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_output_bits, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_trivium_generate_keystream(
                        streams,
                        keystream.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                        num_steps as u32,
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_trivium_generate_keystream(
                        streams,
                        keystream.as_mut(),
                        key.as_ref(),
                        iv.as_ref(),
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        None,
                        num_steps as u32,
                    );
                }
            }
        }
        Ok(keystream)
    }
}
