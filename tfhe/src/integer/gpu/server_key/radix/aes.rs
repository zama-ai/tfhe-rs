use crate::core_crypto::gpu::{
    check_valid_cuda_malloc, check_valid_cuda_malloc_assert_oom, CudaStreams,
};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::{
    cuda_backend_aes_key_expansion, cuda_backend_get_aes_ctr_encrypt_size_on_gpu,
    cuda_backend_get_aes_key_expansion_size_on_gpu, cuda_backend_unchecked_aes_ctr_encrypt,
    PBSType,
};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::Ciphertext;

const NUM_BITS: usize = 64;

impl RadixClientKey {
    pub fn encrypt_u64_for_aes_ctr(&self, data: u64) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(NUM_BITS);
        for i in 0..NUM_BITS {
            let bit = (data >> (NUM_BITS - 1 - i)) & 1;
            blocks.extend(self.encrypt(bit).blocks);
        }
        RadixCiphertext::from(blocks)
    }

    pub fn decrypt_u64_from_aes_ctr(
        &self,
        encrypted_result: &RadixCiphertext,
        num_aes_inputs: usize,
    ) -> Vec<u64> {
        let mut plaintext_results = Vec::with_capacity(num_aes_inputs);
        for i in 0..num_aes_inputs {
            let mut current_block_plaintext: u64 = 0;
            let block_start_index = i * NUM_BITS;
            for j in 0..NUM_BITS {
                let block_slice =
                    &encrypted_result.blocks[block_start_index + j..block_start_index + j + 1];
                let block_radix_ct = RadixCiphertext::from(block_slice.to_vec());
                let decrypted_bit: u64 = self.decrypt(&block_radix_ct);
                current_block_plaintext = (current_block_plaintext << 1) | decrypted_bit;
            }
            plaintext_results.push(current_block_plaintext);
        }
        plaintext_results
    }
}

impl CudaServerKey {
    pub fn aes_ctr(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        start_counter: u64,
        num_aes_inputs: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let gpu_index = streams.gpu_indexes[0];

        let key_expansion_size = self.get_key_expansion_size_on_gpu(streams);
        check_valid_cuda_malloc_assert_oom(key_expansion_size, gpu_index);

        // `parallelism` refers to level of parallelization of the S-box.
        // S-box should process 16 bytes of data: sequentially, or in groups of 2,
        // or in groups of 4, or in groups of 8, or all 16 at the same time.
        // More parallelization leads to higher memory usage. Therefore, we must find a way
        // to maximize parallelization while ensuring that there is still enough memory remaining on
        // the GPU.
        //
        let mut parallelism = 16;

        while parallelism > 0 {
            // `num_aes_inputs` refers to the number of 128-bit ciphertexts that AES will produce.
            //
            let aes_encrypt_size =
                self.get_aes_encrypt_size_on_gpu(num_aes_inputs, parallelism, streams);

            if check_valid_cuda_malloc(aes_encrypt_size, streams.gpu_indexes[0]) {
                let round_keys = self.key_expansion(key, streams);
                let res = self.aes_encrypt(
                    iv,
                    &round_keys,
                    start_counter,
                    num_aes_inputs,
                    parallelism,
                    streams,
                );
                return res;
            }
            parallelism /= 2;
        }

        panic!("Failed to allocate GPU memory for AES, even with the lowest parallelism setting.");
    }

    pub fn aes_ctr_with_fixed_parallelism(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        start_counter: u64,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        assert!(
            [1, 2, 4, 8, 16].contains(&sbox_parallelism),
            "Invalid S-Box parallelism: must be one of [1, 2, 4, 8, 16], got {sbox_parallelism}"
        );

        let gpu_index = streams.gpu_indexes[0];

        let key_expansion_size = self.get_key_expansion_size_on_gpu(streams);
        check_valid_cuda_malloc_assert_oom(key_expansion_size, gpu_index);

        let aes_encrypt_size =
            self.get_aes_encrypt_size_on_gpu(num_aes_inputs, sbox_parallelism, streams);
        check_valid_cuda_malloc_assert_oom(aes_encrypt_size, gpu_index);

        let round_keys = self.key_expansion(key, streams);
        self.aes_encrypt(
            iv,
            &round_keys,
            start_counter,
            num_aes_inputs,
            sbox_parallelism,
            streams,
        )
    }

    pub fn aes_encrypt(
        &self,
        iv: &CudaUnsignedRadixCiphertext,
        round_keys: &CudaUnsignedRadixCiphertext,
        start_counter: u64,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_aes_inputs * NUM_BITS, streams);

        let num_round_key_blocks = 11 * NUM_BITS;

        assert_eq!(
            iv.as_ref().d_blocks.lwe_ciphertext_count().0,
            NUM_BITS,
            "AES IV must contain {NUM_BITS} encrypted bits, but contains {}",
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
            num_aes_inputs * NUM_BITS,
            "AES result must contain {} encrypted bits for {num_aes_inputs} blocks, but contains {}",
            num_aes_inputs * NUM_BITS,
            result.as_ref().d_blocks.lwe_ciphertext_count().0
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_aes_ctr_encrypt(
                        streams,
                        result.as_mut(),
                        iv.as_ref(),
                        round_keys.as_ref(),
                        start_counter,
                        num_aes_inputs as u32,
                        sbox_parallelism as u32,
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
                    cuda_backend_unchecked_aes_ctr_encrypt(
                        streams,
                        result.as_mut(),
                        iv.as_ref(),
                        round_keys.as_ref(),
                        start_counter,
                        num_aes_inputs as u32,
                        sbox_parallelism as u32,
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
        }
        result
    }

    pub fn get_aes_encrypt_size_on_gpu(
        &self,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> u64 {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_aes_ctr_encrypt_size_on_gpu(
                streams,
                num_aes_inputs as u32,
                sbox_parallelism as u32,
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
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_aes_ctr_encrypt_size_on_gpu(
                    streams,
                    num_aes_inputs as u32,
                    sbox_parallelism as u32,
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
                )
            }
        }
    }

    pub fn key_expansion(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let num_round_keys = 11;
        let num_key_bits = 64;
        let mut expanded_keys: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_round_keys * num_key_bits, streams);

        assert_eq!(
            key.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_key_bits,
            "Input key must contain {} encrypted bits, but contains {}",
            num_key_bits,
            key.as_ref().d_blocks.lwe_ciphertext_count().0
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_aes_key_expansion(
                        streams,
                        expanded_keys.as_mut(),
                        key.as_ref(),
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
                    cuda_backend_aes_key_expansion(
                        streams,
                        expanded_keys.as_mut(),
                        key.as_ref(),
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
        }
        expanded_keys
    }

    pub fn get_key_expansion_size_on_gpu(&self, streams: &CudaStreams) -> u64 {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_aes_key_expansion_size_on_gpu(
                streams,
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
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_aes_key_expansion_size_on_gpu(
                    streams,
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
                )
            }
        }
    }
}
