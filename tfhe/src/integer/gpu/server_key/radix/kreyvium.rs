use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_kreyvium_generate_keystream, LweBskGroupingFactor, PBSType,
};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::Ciphertext;

impl RadixClientKey {
    pub fn encrypt_bits_for_kreyvium(&self, bits: &[u64]) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(bits.len());
        for &bit in bits {
            let mut ct = self.encrypt(bit);
            let block = ct.blocks.pop().unwrap();
            blocks.push(block);
        }
        RadixCiphertext::from(blocks)
    }

    pub fn decrypt_bits_from_kreyvium(&self, encrypted_stream: &RadixCiphertext) -> Vec<u8> {
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
    pub fn kreyvium_generate_keystream(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        num_steps: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let num_key_bits = 128;
        let num_iv_bits = 128;

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
                    cuda_backend_kreyvium_generate_keystream(
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
                    cuda_backend_kreyvium_generate_keystream(
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

#[cfg(test)]
mod tests {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::CudaServerKey;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::{IntegerKeyKind, RadixClientKey};
    use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    #[test]
    fn test_gpu_kreyvium_correctness() {
        let streams = CudaStreams::new_multi_gpu();

        let param = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let (raw_cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cpu_cks = RadixClientKey::from((raw_cks, 1));

        let sks = CudaServerKey::new(&cpu_cks, &streams);

        let key_hex = "0053A6F94C9FF24598EB000000000000";
        let iv_hex = "0D74DB42A91077DE45AC000000000000";
        let expected_out_hex = "D1F0303482061111";

        let parse_hex = |s: &str| -> Vec<u64> {
            let mut bits = Vec::new();
            for i in (0..s.len()).step_by(2) {
                let byte = u8::from_str_radix(&s[i..i + 2], 16).unwrap();
                for j in 0..8 {
                    bits.push(((byte >> j) & 1) as u64);
                }
            }
            bits
        };

        let key_bits = parse_hex(key_hex);
        let iv_bits = parse_hex(iv_hex);

        assert_eq!(key_bits.len(), 128);
        assert_eq!(iv_bits.len(), 128);

        let encrypted_key = cpu_cks.encrypt_bits_for_kreyvium(&key_bits);
        let encrypted_iv = cpu_cks.encrypt_bits_for_kreyvium(&iv_bits);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_iv, &streams);

        let d_keystream = sks.kreyvium_generate_keystream(&d_key, &d_iv, 64, &streams);

        let keystream = d_keystream.to_radix_ciphertext(&streams);
        let decrypted_bits = cpu_cks.decrypt_bits_from_kreyvium(&keystream);

        let mut result_hex = String::new();
        for chunk in decrypted_bits.chunks(8) {
            let mut byte = 0u8;
            for (j, &b) in chunk.iter().enumerate() {
                if b == 1 {
                    byte |= 1 << j;
                }
            }
            result_hex.push_str(&format!("{:02X}", byte));
        }

        assert_eq!(result_hex, expected_out_hex);
    }
}
