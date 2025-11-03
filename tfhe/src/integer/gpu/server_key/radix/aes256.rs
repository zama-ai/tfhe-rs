use crate::core_crypto::gpu::{
    check_valid_cuda_malloc, check_valid_cuda_malloc_assert_oom, CudaStreams,
};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::prelude::LweBskGroupingFactor;
use crate::integer::gpu::{
    cuda_backend_aes_key_expansion_256, cuda_backend_get_aes_key_expansion_256_size_on_gpu,
    cuda_backend_unchecked_aes_ctr_256_encrypt, PBSType,
};
use crate::integer::{RadixCiphertext, RadixClientKey};

const NUM_BITS: usize = 128;

impl RadixClientKey {
    pub fn encrypt_2u128_for_aes_ctr_256(&self, key_hi: u128, key_lo: u128) -> RadixCiphertext {
        let ctxt_hi = self.encrypt_u128_for_aes_ctr(key_hi);
        let ctxt_lo = self.encrypt_u128_for_aes_ctr(key_lo);

        let mut combined_blocks = ctxt_hi.blocks;
        combined_blocks.extend(ctxt_lo.blocks);

        RadixCiphertext::from(combined_blocks)
    }
}

impl CudaServerKey {
    /// Computes homomorphically AES-256 encryption in CTR mode.
    ///
    /// This function performs AES-256 encryption on an encrypted 128-bit IV
    /// using an encrypted 256-bit key. It operates in Counter (CTR) mode, generating
    /// `num_aes_inputs` encrypted ciphertexts starting from the `start_counter` value
    /// (which is typically added to the IV).
    ///
    /// The 256-bit key must be prepared using `encrypt_2u128_for_aes_ctr_256` and
    /// the 128-bit IV using `encrypt_u128_for_aes_ctr`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::GpuIndex;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// // AES bit-wise operations require 1-block ciphertexts (for encrypting single bits).
    /// let num_blocks = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// let key_hi: u128 = 0x603deb1015ca71be2b73aef0857d7781;
    /// let key_lo: u128 = 0x1f352c073b6108d72d9810a30914dff4;
    /// let iv: u128 = 0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff;
    /// let num_aes_inputs = 2; // Produce 2 128-bits ciphertexts
    /// let start_counter = 0u128;
    ///
    /// // Encrypt the 256-bit key and 128-bit IV bit by bit
    /// let ct_key = cks.encrypt_2u128_for_aes_ctr_256(key_hi, key_lo);
    /// let ct_iv = cks.encrypt_u128_for_aes_ctr(iv);
    ///
    /// let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
    /// let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);
    ///
    /// let d_ct_res = sks.aes_ctr_256(&d_key, &d_iv, start_counter, num_aes_inputs, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    ///
    /// let fhe_results = cks.decrypt_u128_from_aes_ctr(&ct_res, num_aes_inputs);
    ///
    /// // Verify:
    /// let expected_results: Vec<u128> = vec![
    ///     0xbdf7df1591716335e9a8b15c860c502,
    ///     0x5a6e699d536119065433863c8f657b94,
    /// ];
    /// assert_eq!(fhe_results, expected_results);
    /// ```
    pub fn aes_ctr_256(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        start_counter: u128,
        num_aes_inputs: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let gpu_index = streams.gpu_indexes[0];

        let key_expansion_size = self.get_key_expansion_256_size_on_gpu(streams);
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
                let round_keys = self.key_expansion_256(key, streams);
                let res = self.aes_256_encrypt(
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

    pub fn aes_ctr_256_with_fixed_parallelism(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        iv: &CudaUnsignedRadixCiphertext,
        start_counter: u128,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        assert!(
            [1, 2, 4, 8, 16].contains(&sbox_parallelism),
            "Invalid S-Box parallelism: must be one of [1, 2, 4, 8, 16], got {sbox_parallelism}"
        );

        let gpu_index = streams.gpu_indexes[0];

        let key_expansion_size = self.get_key_expansion_256_size_on_gpu(streams);
        check_valid_cuda_malloc_assert_oom(key_expansion_size, gpu_index);

        let aes_encrypt_size =
            self.get_aes_encrypt_size_on_gpu(num_aes_inputs, sbox_parallelism, streams);
        check_valid_cuda_malloc_assert_oom(aes_encrypt_size, gpu_index);

        let round_keys = self.key_expansion_256(key, streams);
        self.aes_256_encrypt(
            iv,
            &round_keys,
            start_counter,
            num_aes_inputs,
            sbox_parallelism,
            streams,
        )
    }

    pub fn aes_256_encrypt(
        &self,
        iv: &CudaUnsignedRadixCiphertext,
        round_keys: &CudaUnsignedRadixCiphertext,
        start_counter: u128,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_aes_inputs * 128, streams);

        let num_round_key_blocks = 15 * NUM_BITS;

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
      num_aes_inputs * 128,
      "AES result must contain {} encrypted bits for {num_aes_inputs} blocks, but contains {}",
      num_aes_inputs * 128,
      result.as_ref().d_blocks.lwe_ciphertext_count().0
    );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_unchecked_aes_ctr_256_encrypt(
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
                    cuda_backend_unchecked_aes_ctr_256_encrypt(
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

    pub fn key_expansion_256(
        &self,
        key: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let num_round_keys = 15;
        let input_key_bits = 256;
        let round_key_bits = 128;

        let mut expanded_keys: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_round_keys * round_key_bits, streams);

        assert_eq!(
            key.as_ref().d_blocks.lwe_ciphertext_count().0,
            input_key_bits,
            "Input key must contain {} encrypted bits, but contains {}",
            input_key_bits,
            key.as_ref().d_blocks.lwe_ciphertext_count().0
        );

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_aes_key_expansion_256(
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
                    cuda_backend_aes_key_expansion_256(
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

    pub fn get_key_expansion_256_size_on_gpu(&self, streams: &CudaStreams) -> u64 {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_backend_get_aes_key_expansion_256_size_on_gpu(
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
                )
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_aes_key_expansion_256_size_on_gpu(
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
