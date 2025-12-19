use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{cuda_backend_trivium_generate_keystream, LweBskGroupingFactor, PBSType};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::Ciphertext;

impl RadixClientKey {
    pub fn encrypt_bits_from_u64_slice_to_radix_ciphertext(&self, bits: &[u64]) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(bits.len());
        for &bit in bits {
            let mut ct = self.encrypt(bit);
            let block = ct.blocks.pop().unwrap();
            blocks.push(block);
        }
        RadixCiphertext::from(blocks)
    }

    pub fn decrypt_bits_from_radix_ciphertext_to_vec_u8(
        &self,
        encrypted_stream: &RadixCiphertext,
    ) -> Vec<u8> {
        let mut decrypted_bits = Vec::with_capacity(encrypted_stream.blocks.len());
        for block in &encrypted_stream.blocks {
            let tmp_radix = RadixCiphertext::from(vec![block.clone()]);
            let val: u64 = self.decrypt(&tmp_radix);
            decrypted_bits.push(val as u8);
        }
        decrypted_bits
    }
}

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
    ) -> CudaUnsignedRadixCiphertext {
        let num_key_bits = 80;
        let num_iv_bits = 80;

        assert_eq!(
            key.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_key_bits,
            "Input key must contain {} encrypted bits, but contains {}",
            num_key_bits,
            key.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        assert_eq!(
            iv.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_iv_bits,
            "Input IV must contain {} encrypted bits, but contains {}",
            num_iv_bits,
            iv.as_ref().d_blocks.lwe_ciphertext_count().0
        );

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
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        d_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        PBSType::Classical,
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
                        d_multibit_bsk.glwe_dimension,
                        d_multibit_bsk.polynomial_size,
                        d_multibit_bsk.input_lwe_dimension,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_multibit_bsk.decomp_level_count,
                        d_multibit_bsk.decomp_base_log,
                        d_multibit_bsk.grouping_factor,
                        PBSType::MultiBit,
                        None,
                        num_steps as u32,
                    );
                }
            }
        }
        keystream
    }
}
