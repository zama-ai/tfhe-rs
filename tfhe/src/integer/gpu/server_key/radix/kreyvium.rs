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
    use rand::Rng;
    use std::fmt::Write;

    fn kreyvium_clear_reference(
        key_bits: &[u64; 128],
        iv_bits: &[u64; 128],
        num_steps: usize,
    ) -> Vec<u8> {
        let mut a: [u64; 93] = [0; 93];
        let mut b: [u64; 84] = [0; 84];
        let mut c: [u64; 111] = [0; 111];
        let mut k: [u64; 128] = *key_bits;
        let mut iv: [u64; 128] = *iv_bits;

        for i in 0..93 {
            a[i] = key_bits[128 - 93 + i];
        }
        for i in 0..84 {
            b[i] = iv_bits[128 - 84 + i];
        }
        for i in 0..44 {
            c[111 - 44 + i] = iv_bits[i];
        }
        for i in 0..66 {
            c[i + 1] = 1;
        }

        k.reverse();
        iv.reverse();

        let mut cursor_a: usize = 0;
        let mut cursor_b: usize = 0;
        let mut cursor_c: usize = 0;
        let mut cursor_k: usize = 0;
        let mut cursor_iv: usize = 0;

        let idx_a = |cursor: usize, i: usize| -> usize { (93 + cursor - i - 1) % 93 };
        let idx_b = |cursor: usize, i: usize| -> usize { (84 + cursor - i - 1) % 84 };
        let idx_c = |cursor: usize, i: usize| -> usize { (111 + cursor - i - 1) % 111 };
        let idx_k = |cursor: usize, i: usize| -> usize { (128 + cursor - i - 1) % 128 };
        let idx_iv = |cursor: usize, i: usize| -> usize { (128 + cursor - i - 1) % 128 };

        let mut output = Vec::with_capacity(num_steps);

        for step in 0..num_steps {
            let is_init = step < 1152;

            let k_val = k[idx_k(cursor_k, 127)];
            let iv_val = iv[idx_iv(cursor_iv, 127)];

            let a1 = a[idx_a(cursor_a, 65)];
            let a2 = a[idx_a(cursor_a, 92)];
            let a3 = a[idx_a(cursor_a, 91)];
            let a4 = a[idx_a(cursor_a, 90)];
            let a5 = a[idx_a(cursor_a, 68)];

            let b1 = b[idx_b(cursor_b, 68)];
            let b2 = b[idx_b(cursor_b, 83)];
            let b3 = b[idx_b(cursor_b, 82)];
            let b4 = b[idx_b(cursor_b, 81)];
            let b5 = b[idx_b(cursor_b, 77)];

            let c1 = c[idx_c(cursor_c, 65)];
            let c2 = c[idx_c(cursor_c, 110)];
            let c3 = c[idx_c(cursor_c, 109)];
            let c4 = c[idx_c(cursor_c, 108)];
            let c5 = c[idx_c(cursor_c, 86)];

            let temp_a = a1 ^ a2;
            let temp_b = b1 ^ b2;
            let temp_c = c1 ^ c2 ^ k_val;

            let new_a = (c3 & c4) ^ a5 ^ temp_c;
            let new_b = (a3 & a4) ^ b5 ^ temp_a ^ iv_val;
            let new_c = (b3 & b4) ^ c5 ^ temp_b;

            let o = temp_a ^ temp_b ^ temp_c;

            if !is_init {
                output.push(o as u8);
            }

            a[cursor_a] = new_a;
            cursor_a = (cursor_a + 1) % 93;

            b[cursor_b] = new_b;
            cursor_b = (cursor_b + 1) % 84;

            c[cursor_c] = new_c;
            cursor_c = (cursor_c + 1) % 111;

            cursor_k = (cursor_k + 1) % 128;
            cursor_iv = (cursor_iv + 1) % 128;
        }

        output
    }

    fn bits_to_hex(bits: &[u8]) -> String {
        let mut result = String::new();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (j, &b) in chunk.iter().enumerate() {
                if b == 1 {
                    byte |= 1 << j;
                }
            }
            write!(result, "{byte:02X}").unwrap();
        }
        result
    }

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

        let result_hex = bits_to_hex(&decrypted_bits);

        assert_eq!(result_hex, expected_out_hex);
    }

    #[test]
    fn test_gpu_kreyvium_vs_clear_random() {
        let streams = CudaStreams::new_multi_gpu();

        let param = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let (raw_cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cpu_cks = RadixClientKey::from((raw_cks, 1));

        let sks = CudaServerKey::new(&cpu_cks, &streams);

        let mut rng = rand::thread_rng();

        let mut key_bits_arr: [u64; 128] = [0; 128];
        let mut iv_bits_arr: [u64; 128] = [0; 128];

        for i in 0..128 {
            key_bits_arr[i] = rng.gen_range(0..2);
            iv_bits_arr[i] = rng.gen_range(0..2);
        }

        let key_bits_vec: Vec<u64> = key_bits_arr.to_vec();
        let iv_bits_vec: Vec<u64> = iv_bits_arr.to_vec();

        let num_output_bits = 64 * 50;
        let expected_output =
            kreyvium_clear_reference(&key_bits_arr, &iv_bits_arr, 1152 + num_output_bits);

        let encrypted_key = cpu_cks.encrypt_bits_for_kreyvium(&key_bits_vec);
        let encrypted_iv = cpu_cks.encrypt_bits_for_kreyvium(&iv_bits_vec);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&encrypted_iv, &streams);

        let d_keystream = sks.kreyvium_generate_keystream(&d_key, &d_iv, num_output_bits, &streams);

        let keystream = d_keystream.to_radix_ciphertext(&streams);
        let decrypted_bits = cpu_cks.decrypt_bits_from_kreyvium(&keystream);

        let gpu_hex = bits_to_hex(&decrypted_bits);
        let clear_hex = bits_to_hex(&expected_output);

        assert_eq!(
            gpu_hex, clear_hex,
            "GPU FHE result does not match clear CPU reference.\nKey bits: {key_bits_arr:?}\nIV bits: {iv_bits_arr:?}\nGPU result: {gpu_hex}\nClear result: {clear_hex}"
        );
    }
}
