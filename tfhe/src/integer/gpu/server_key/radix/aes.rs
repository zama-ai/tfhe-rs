use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::{
    unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async,
    unchecked_aes_sbox_byte_integer_radix_kb_assign_async, PBSType,
};

impl CudaServerKey {
    pub fn aes_encrypt(
        &self,
        iv: &CudaUnsignedRadixCiphertext,
        round_keys: &CudaUnsignedRadixCiphertext,
        counter_value: u128,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let result = unsafe { self.aes_encrypt_async(iv, round_keys, counter_value, streams) };
        streams.synchronize();
        result
    }

    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub unsafe fn aes_encrypt_async(
        &self,
        iv: &CudaUnsignedRadixCiphertext,
        round_keys: &CudaUnsignedRadixCiphertext,
        counter_value: u128,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut state_to_encrypt = iv.duplicate_async(streams);

        let num_state_blocks = 128;
        let num_round_key_blocks = 11 * 128;

        assert_eq!(
            state_to_encrypt.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_state_blocks,
            "AES state must contain {} encrypted bits, but contains {}",
            num_state_blocks,
            state_to_encrypt.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        assert_eq!(
            round_keys.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_round_key_blocks,
            "AES round_keys must contain {} encrypted bits, but contains {}",
            num_round_key_blocks,
            round_keys.as_ref().d_blocks.lwe_ciphertext_count().0
        );

        let counter_bits_le = (0..128)
            .map(|i| ((counter_value >> i) & 1) as u64)
            .collect::<Vec<_>>();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async(
                    streams,
                    state_to_encrypt.as_mut(),
                    round_keys.as_ref(),
                    &counter_bits_le,
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async(
                    streams,
                    state_to_encrypt.as_mut(),
                    round_keys.as_ref(),
                    &counter_bits_le,
                    &d_multibit_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk.glwe_dimension,
                    d_multibit_bsk.polynomial_size,
                    d_multibit_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_multibit_bsk.decomp_level_count,
                    d_multibit_bsk.decomp_base_log,
                    d_multibit_bsk.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }
        state_to_encrypt
    }

    pub fn aes_sbox_byte(&self, byte: &mut CudaUnsignedRadixCiphertext, streams: &CudaStreams) {
        unsafe { self.aes_sbox_byte_async(byte, streams) }
        streams.synchronize();
    }

    /// # Safety
    ///
    /// - [CudaStreams::synchronize] __must__ be called after this function as soon as
    ///   synchronization is required
    pub unsafe fn aes_sbox_byte_async(
        &self,
        byte: &mut CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) {
        assert_eq!(
            byte.as_ref().d_blocks.lwe_ciphertext_count().0,
            8,
            "S-box attend exactement 8 bits chiffrés (un octet)"
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_aes_sbox_byte_integer_radix_kb_assign_async(
                    streams,
                    byte.as_mut(),
                    &d_bsk.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    PBSType::Classical,
                    d_bsk.d_ms_noise_reduction_key.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_mb) => {
                unchecked_aes_sbox_byte_integer_radix_kb_assign_async(
                    streams,
                    byte.as_mut(),
                    &d_mb.d_vec,
                    &self.key_switching_key.d_vec,
                    self.message_modulus,
                    self.carry_modulus,
                    d_mb.glwe_dimension,
                    d_mb.polynomial_size,
                    d_mb.input_lwe_dimension,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_mb.decomp_level_count,
                    d_mb.decomp_base_log,
                    d_mb.grouping_factor,
                    PBSType::MultiBit,
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::integer::gpu::gen_keys_radix_gpu;
    use crate::integer::{RadixCiphertext, RadixClientKey};
    use crate::shortint::ciphertext::Ciphertext;
    use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use std::time::Instant;

    const S_BOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    fn u128_to_bits(n: u128) -> Vec<u64> {
        (0..128).map(|i| ((n >> (127 - i)) & 1) as u64).collect()
    }

    fn bits_to_u128(bits: &[u64]) -> u128 {
        bits.iter().fold(0, |acc, &bit| (acc << 1) | (bit as u128))
    }

    fn u8_to_bits(n: u8) -> Vec<u64> {
        (0..8).map(|i| ((n >> (7 - i)) & 1) as u64).collect()
    }
    fn bits_to_u8(bits: &[u64]) -> u8 {
        bits.iter().fold(0u8, |acc, &bit| (acc << 1) | (bit as u8))
    }

    fn encrypt_bits(cks: &RadixClientKey, bits: &[u64]) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(bits.len());
        for &bit in bits {
            blocks.extend(cks.encrypt(bit).blocks);
        }
        RadixCiphertext::from(blocks)
    }

    fn decrypt_bits(cks: &RadixClientKey, ct: &RadixCiphertext) -> Vec<u64> {
        ct.blocks
            .iter()
            .map(|block| {
                let temp_ct = RadixCiphertext::from(vec![block.clone()]);
                cks.decrypt(&temp_ct)
            })
            .collect()
    }

    fn plain_key_expansion(key: u128) -> Vec<u128> {
        const RCON: [u32; 10] = [
            0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
            0x80000000, 0x1B000000, 0x36000000,
        ];

        let mut words = [0u32; 44];
        for (i, word) in words.iter_mut().enumerate().take(4) {
            *word = (key >> (96 - (i * 32))) as u32;
        }

        for i in 4..44 {
            let mut temp = words[i - 1];
            if i % 4 == 0 {
                temp = temp.rotate_left(8);
                let mut sub_bytes = 0u32;
                for j in 0..4 {
                    let byte = (temp >> (24 - j * 8)) as u8;
                    sub_bytes |= (S_BOX[byte as usize] as u32) << (24 - j * 8);
                }
                temp = sub_bytes ^ RCON[i / 4 - 1];
            }
            words[i] = words[i - 4] ^ temp;
        }

        words
            .chunks_exact(4)
            .map(|chunk| {
                ((chunk[0] as u128) << 96)
                    | ((chunk[1] as u128) << 64)
                    | ((chunk[2] as u128) << 32)
                    | (chunk[3] as u128)
            })
            .collect()
    }

    #[test]
    fn test_samples_of_sbox() {
        let samples: [u8; 12] = [
            0x00, 0x01, 0x02, 0x0f, 0x10, 0x20, 0x5c, 0x7f, 0x80, 0x9a, 0xfe, 0xff,
        ];

        let gpu_index = 0;
        let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
        let (cks, sks) = gen_keys_radix_gpu(
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            1,
            &streams,
        );

        for &p in &samples {
            let p_bits = u8_to_bits(p);
            let ct_radix_cpu = encrypt_bits(&cks, &p_bits);
            let mut d_byte =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_radix_cpu, &streams);

            sks.aes_sbox_byte(&mut d_byte, &streams);

            let result_radix_cpu = d_byte.to_radix_ciphertext(&streams);
            let decrypted_result_bits = decrypt_bits(&cks, &result_radix_cpu);
            let y = bits_to_u8(&decrypted_result_bits);

            assert_eq!(y, S_BOX[p as usize], "SBox({p:#04x})");
        }
    }

    #[test]
    fn test_encrypt_aes() {
        let gpu_index = 0;
        let (cks, sks) = {
            let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
            gen_keys_radix_gpu(
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                1,
                &streams,
            )
        };

        let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
        let iv: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;

        let nist_expected_outputs: [u128; 4] = [
            0xec8cdf7398607cb0f2d21675ea9ea1e4,
            0x362b7c3c6773516318a077d7fc5073ae,
            0x6a2cc3787889374fbeb4c81b17ba6c44,
            0xe89c399ff0f198c6d40a31db156cabfe,
        ];

        let p_round_keys_bits: Vec<u64> = plain_key_expansion(key)
            .iter()
            .flat_map(|&k| u128_to_bits(k))
            .collect();
        let ct_round_keys_radix_cpu = encrypt_bits(&cks, &p_round_keys_bits);
        let p_iv_bits = u128_to_bits(iv);
        let ct_iv_radix_cpu = encrypt_bits(&cks, &p_iv_bits);

        let number_of_outputs = 4;

        let overall_start = Instant::now();

        for (i, &expected_output) in nist_expected_outputs
            .iter()
            .enumerate()
            .take(number_of_outputs)
        {
            let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
            let d_round_keys = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &ct_round_keys_radix_cpu,
                &streams,
            );
            let d_iv =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv_radix_cpu, &streams);

            let t0 = Instant::now();
            let d_encrypted_state = sks.aes_encrypt(&d_iv, &d_round_keys, i as u128, &streams);
            let t_elapsed = t0.elapsed();

            println!(
                "[Benchmark] aes_encrypt() time for block {}: {:.3} ms",
                i,
                t_elapsed.as_secs_f64() * 1000.0,
            );

            let result_radix_cpu = d_encrypted_state.to_radix_ciphertext(&streams);
            let decrypted_bits = decrypt_bits(&cks, &result_radix_cpu);
            let y = bits_to_u128(&decrypted_bits);

            assert_eq!(y, expected_output, "block {i}");
        }

        let overall_elapsed = overall_start.elapsed();

        println!("\nAES test passed!");

        println!(
            "\n[Benchmark] Total wall time for {} sequential block(s): {:.3} ms",
            number_of_outputs,
            overall_elapsed.as_secs_f64() * 1000.0
        );
        println!(
            "[Benchmark] Average time per block (based on wall time): {:.3} ms",
            overall_elapsed.as_secs_f64() * 1000.0 / number_of_outputs as f64
        );
    }
}
