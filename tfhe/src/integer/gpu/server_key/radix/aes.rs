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

const NUM_BITS: usize = 128;

impl RadixClientKey {
    /// Encrypts a 128-bit block for homomorphic AES evaluation.
    ///
    /// This function prepares a 128-bit plaintext block (like an AES key or IV)
    /// for homomorphic processing by decomposing it into its 128 constituent bits
    /// and encrypting each bit individually with FHE.
    ///
    /// The process is as follows:
    /// ```text
    /// // INPUT: A 128-bit plaintext block
    /// Plaintext block (u128): 0x2b7e1516...
    ///       |
    ///       V
    /// // 1. Decompose the block into individual bits
    /// Individual bits: [b127, b126, ..., b1, b0]
    ///       |
    ///       V
    /// // 2. Encrypt each bit individually using FHE
    /// `self.encrypt(bit)` is applied to each bit
    ///       |
    ///       V
    /// // 3. Collect the resulting bit-ciphertexts
    /// Ciphertexts: [Ct(b127), Ct(b126), ..., Ct(b0)]
    ///       |
    ///       V
    /// // 4. Group the bit-ciphertexts into a single RadixCiphertext
    /// //    representing the full encrypted block.
    /// // OUTPUT: A RadixCiphertext
    /// ```
    pub fn encrypt_u128_for_aes_ctr(&self, data: u128) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(NUM_BITS);
        for i in 0..NUM_BITS {
            let bit = ((data >> (NUM_BITS - 1 - i)) & 1) as u64;
            blocks.extend(self.encrypt(bit).blocks);
        }
        RadixCiphertext::from(blocks)
    }

    /// Decrypts a `RadixCiphertext` containing one or more 128-bit blocks
    /// that were homomorphically processed.
    ///
    /// This function reverses the encryption process by decrypting each individual
    /// bit-ciphertext and reassembling them into 128-bit plaintext blocks.
    ///
    /// The process is as follows:
    /// ```text
    /// // INPUT: RadixCiphertext containing one or more encrypted blocks
    /// Ciphertext collection: [Ct(b127), ..., Ct(b0), Ct(b'127), ..., Ct(b'0), ...]
    ///       |
    ///       | (For each sequence of 128 bit-ciphertexts)
    ///       V
    /// // 1. Decrypt each bit's ciphertext individually
    /// `self.decrypt(Ct)` is applied to each bit-ciphertext
    ///       |
    ///       V
    /// // 2. Collect the resulting plaintext bits
    /// Plaintext bits: [b127, b126, ..., b0]
    ///       |
    ///       V
    /// // 3. Assemble the bits back into a 128-bit block
    /// Reconstruction: ( ...((b127 << 1) | b126) << 1 | ... ) | b0
    ///       |
    ///       V
    /// // OUTPUT: A vector of plaintext u128 blocks
    /// Plaintext u128s: [0x..., ...]
    /// ```
    pub fn decrypt_u128_from_aes_ctr(
        &self,
        encrypted_result: &RadixCiphertext,
        num_aes_inputs: usize,
    ) -> Vec<u128> {
        let mut plaintext_results = Vec::with_capacity(num_aes_inputs);
        for i in 0..num_aes_inputs {
            let mut current_block_plaintext: u128 = 0;
            let block_start_index = i * NUM_BITS;
            for j in 0..NUM_BITS {
                let block_slice =
                    &encrypted_result.blocks[block_start_index + j..block_start_index + j + 1];
                let block_radix_ct = RadixCiphertext::from(block_slice.to_vec());
                let decrypted_bit: u128 = self.decrypt(&block_radix_ct);
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
        start_counter: u128,
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
        start_counter: u128,
        num_aes_inputs: usize,
        sbox_parallelism: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_aes_inputs * 128, streams);

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
            num_aes_inputs * 128,
            "AES result must contain {} encrypted bits for {num_aes_inputs} blocks, but contains {}",
            num_aes_inputs * 128,
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
        let num_key_bits = 128;
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
