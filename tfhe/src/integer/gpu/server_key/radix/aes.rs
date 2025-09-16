use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::{unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async, PBSType};

impl CudaServerKey {
    pub fn aes_encrypt(
        &self,
        iv: &CudaUnsignedRadixCiphertext,
        round_keys: &CudaUnsignedRadixCiphertext,
        start_counter: u128,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let result =
            unsafe { self.aes_encrypt_async(iv, round_keys, start_counter, num_blocks, streams) };
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
        start_counter: u128,
        num_blocks: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_blocks * 128, streams);

        let num_iv_blocks = 128;
        let num_round_key_blocks = 11 * 128;

        assert_eq!(
            iv.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_iv_blocks,
            "AES IV must contain {num_iv_blocks} encrypted bits, but contains {}",
            iv.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        assert_eq!(
            round_keys.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_round_key_blocks,
            "AES round_keys must contain {num_round_key_blocks} encrypted bits, but contains {}",
            round_keys.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        assert_eq!(
            result.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_blocks * 128,
            "AES result must contain {} encrypted bits for {num_blocks} blocks, but contains {}",
            num_blocks * 128,
            result.as_ref().d_blocks.lwe_ciphertext_count().0
        );

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async(
                    streams,
                    result.as_mut(),
                    iv.as_ref(),
                    round_keys.as_ref(),
                    start_counter,
                    num_blocks as u32,
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
                    d_bsk.ms_noise_reduction_configuration.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                unchecked_aes_ctr_encrypt_integer_radix_kb_assign_async(
                    streams,
                    result.as_mut(),
                    iv.as_ref(),
                    round_keys.as_ref(),
                    start_counter,
                    num_blocks as u32,
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
        result
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = S_BOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let original = *state;
        state[1] = original[5];
        state[5] = original[9];
        state[9] = original[13];
        state[13] = original[1];

        state[2] = original[10];
        state[6] = original[14];
        state[10] = original[2];
        state[14] = original[6];

        state[3] = original[15];
        state[7] = original[3];
        state[11] = original[7];
        state[15] = original[11];
    }

    fn gmul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    fn mix_columns(state: &mut [u8; 16]) {
        let original = *state;
        for i in 0..4 {
            let col = i * 4;
            state[col] = gmul(original[col], 2)
                ^ gmul(original[col + 1], 3)
                ^ original[col + 2]
                ^ original[col + 3];
            state[col + 1] = original[col]
                ^ gmul(original[col + 1], 2)
                ^ gmul(original[col + 2], 3)
                ^ original[col + 3];
            state[col + 2] = original[col]
                ^ original[col + 1]
                ^ gmul(original[col + 2], 2)
                ^ gmul(original[col + 3], 3);
            state[col + 3] = gmul(original[col], 3)
                ^ original[col + 1]
                ^ original[col + 2]
                ^ gmul(original[col + 3], 2);
        }
    }

    fn add_round_key(state: &mut [u8; 16], round_key: u128) {
        let key_bytes = round_key.to_be_bytes();
        for i in 0..16 {
            state[i] ^= key_bytes[i];
        }
    }

    fn plain_aes_encrypt_block(block_bytes: &mut [u8; 16], expanded_keys: &[u128]) {
        add_round_key(block_bytes, expanded_keys[0]);

        for round_key in expanded_keys.iter().take(10).skip(1) {
            sub_bytes(block_bytes);
            shift_rows(block_bytes);
            mix_columns(block_bytes);
            add_round_key(block_bytes, *round_key);
        }

        sub_bytes(block_bytes);
        shift_rows(block_bytes);
        add_round_key(block_bytes, expanded_keys[10]);
    }

    fn plain_aes_ctr(num_blocks: usize, iv: u128, key: u128) -> Vec<u128> {
        let expanded_keys = plain_key_expansion(key);
        let mut results = Vec::with_capacity(num_blocks);

        for i in 0..num_blocks {
            let counter_value = iv.wrapping_add(i as u128);
            let mut block = counter_value.to_be_bytes();
            plain_aes_encrypt_block(&mut block, &expanded_keys);
            results.push(u128::from_be_bytes(block));
        }

        results
    }

    #[test]
    fn test_aes_1000_blocks() {
        let streams = CudaStreams::new_multi_gpu();
        let (cks, sks) = gen_keys_radix_gpu(
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            1,
            &streams,
        );

        let key: u128 = 0x2b7e151628aed2a6abf7158809cf4f3c;
        let iv: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;
        let num_blocks: usize = 1000;
        let start_counter: u128 = 0;

        println!("\n[Test] Starting FHE AES-CTR test for {num_blocks} blocks...");

        let p_round_keys_bits: Vec<u64> = plain_key_expansion(key)
            .iter()
            .flat_map(|&k| u128_to_bits(k))
            .collect();
        let ct_round_keys_radix_cpu = encrypt_bits(&cks, &p_round_keys_bits);
        let p_iv_bits = u128_to_bits(iv);
        let ct_iv_radix_cpu = encrypt_bits(&cks, &p_iv_bits);

        let d_round_keys =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_round_keys_radix_cpu, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv_radix_cpu, &streams);

        let t0 = Instant::now();
        let d_encrypted_states =
            sks.aes_encrypt(&d_iv, &d_round_keys, start_counter, num_blocks, &streams);
        let fhe_duration = t0.elapsed();
        println!(
            "[FHE] Encryption of {num_blocks} blocks finished in {:.3} ms.",
            fhe_duration.as_secs_f64() * 1000.0
        );

        let result_radix_cpu = d_encrypted_states.to_radix_ciphertext(&streams);
        let mut fhe_results = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let start = i * 128;
            let end = (i + 1) * 128;
            let block_slice = &result_radix_cpu.blocks[start..end];
            let block_radix_ct = RadixCiphertext::from(block_slice.to_vec());
            let decrypted_bits = decrypt_bits(&cks, &block_radix_ct);
            fhe_results.push(bits_to_u128(&decrypted_bits));
        }

        let t0 = Instant::now();
        let plain_results = plain_aes_ctr(num_blocks, iv, key);
        let plain_duration = t0.elapsed();
        println!(
            "[CPU] Encryption of {num_blocks} blocks finished in {:.3} ms.",
            plain_duration.as_secs_f64() * 1000.0
        );

        println!("[Validation] Comparing FHE and plaintext results...");
        assert_eq!(fhe_results.len(), num_blocks);
        assert_eq!(plain_results.len(), num_blocks);

        if num_blocks <= 16 {
            println!("\n[Results per block]");
            for i in 0..num_blocks {
                println!(
                    "Block {i:02}: FHE = {:#034x}, Plain = {:#034x}",
                    fhe_results[i], plain_results[i]
                );
            }
        }

        let mut failures = Vec::new();
        for i in 0..num_blocks {
            if fhe_results[i] != plain_results[i] {
                let error_message = format!(
                    "  [FAILURE] Block {i}: Expected (plain): {:#034x}, Got (FHE): {:#034x}",
                    plain_results[i], fhe_results[i]
                );
                failures.push(error_message);
            }
        }

        assert!(
            failures.is_empty(),
            "\nFHE AES test failed with {} errors over {num_blocks} blocks:\n{}",
            failures.len(),
            failures.join("\n")
        );

        println!("\n[SUCCESS] AES-CTR test for {num_blocks} blocks passed!");
    }
}
