use crate::core_crypto::gpu::{check_valid_cuda_malloc_assert_oom, CudaStreams};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use crate::integer::gpu::{
    cuda_backend_get_prince_key_prep_size_on_gpu, cuda_backend_get_prince_size_on_gpu,
    cuda_backend_prince, cuda_backend_prince_key_prep,
};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::Ciphertext;

const NUM_U2_BLOCKS: usize = 32;
const NUM_BITS: usize = 64;

/// Prepared PRINCEv2 key material for one direction: the raw key halves plus
/// the key bits and 3-bit key parities that the fused rounds absorb levelled.
///
/// The direction is baked into the material, so the fields stay private:
/// flipping `is_decrypt` afterwards would silently give wrong results.
pub struct CudaPrinceKeys {
    k0: CudaUnsignedRadixCiphertext,              // NUM_U2_BLOCKS
    k1: CudaUnsignedRadixCiphertext,              // NUM_U2_BLOCKS
    key_bits_first: CudaUnsignedRadixCiphertext,  // NUM_BITS
    key_bits_second: CudaUnsignedRadixCiphertext, // NUM_BITS
    kap_bw_first: CudaUnsignedRadixCiphertext,    // NUM_BITS
    kap_bw_second: CudaUnsignedRadixCiphertext,   // NUM_BITS
    kap_mid_first: CudaUnsignedRadixCiphertext,   // NUM_BITS
    is_decrypt: bool,
}

impl CudaPrinceKeys {
    /// `true` if this material was prepared for decryption.
    pub fn is_decrypt(&self) -> bool {
        self.is_decrypt
    }
}

impl RadixClientKey {
    /// Encrypts a 64-bit block for homomorphic PRINCEv2 evaluation as 32
    /// shortint blocks of 2-bit nibbles, MSB first. The client key must be
    /// generated with `num_blocks = 1` and 2_2 parameters.
    pub fn encrypt_u64_for_prince(&self, data: u64) -> RadixCiphertext {
        let mut blocks: Vec<Ciphertext> = Vec::with_capacity(NUM_U2_BLOCKS);
        for i in 0..NUM_U2_BLOCKS {
            let nibble = (data >> (62 - 2 * i)) & 3;
            blocks.extend(self.encrypt(nibble).blocks);
        }
        RadixCiphertext::from(blocks)
    }

    /// Encrypts a batch of 64-bit blocks, one after the other, in the layout
    /// `prince_encrypt` expects for `num_prince_inputs > 1`.
    pub fn encrypt_u64s_for_prince(&self, data: &[u64]) -> RadixCiphertext {
        let mut blocks = Vec::with_capacity(data.len() * NUM_U2_BLOCKS);
        for &value in data {
            blocks.extend(self.encrypt_u64_for_prince(value).blocks);
        }
        RadixCiphertext::from(blocks)
    }

    /// Decrypts `num_prince_inputs` 64-bit blocks produced by the homomorphic
    /// PRINCEv2 evaluation.
    pub fn decrypt_u64_from_prince(
        &self,
        encrypted_result: &RadixCiphertext,
        num_prince_inputs: usize,
    ) -> Vec<u64> {
        let mut plaintext_results = Vec::with_capacity(num_prince_inputs);
        for i in 0..num_prince_inputs {
            let mut current_block_plaintext: u64 = 0;
            let block_start_index = i * NUM_U2_BLOCKS;
            for j in 0..NUM_U2_BLOCKS {
                let block_slice =
                    &encrypted_result.blocks[block_start_index + j..block_start_index + j + 1];
                let block_radix_ct = RadixCiphertext::from(block_slice.to_vec());
                let decrypted_nibble: u64 = self.decrypt(&block_radix_ct);
                current_block_plaintext = (current_block_plaintext << 2) | (decrypted_nibble & 3);
            }
            plaintext_results.push(current_block_plaintext);
        }
        plaintext_results
    }
}

impl CudaServerKey {
    /// Computes homomorphically `num_prince_inputs` PRINCEv2 encryptions with
    /// key halves `k0`, `k1`. Requires 2_2 parameters and fresh operands: the
    /// input key xor packs `4 * m + k`, which spends their whole noise budget.
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
    /// // PRINCE nibble-wise operations require 1-block ciphertexts.
    /// let num_blocks = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(
    ///     PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ///     num_blocks,
    ///     &streams,
    /// );
    ///
    /// // Test vector from [BEK+20, Appendix B]
    /// let message: u64 = 0x0123456789abcdef;
    /// let k0: u64 = 0x0123456789abcdef;
    /// let k1: u64 = 0xfedcba9876543210;
    /// let num_prince_inputs = 1;
    ///
    /// let ct_message = cks.encrypt_u64_for_prince(message);
    /// let ct_k0 = cks.encrypt_u64_for_prince(k0);
    /// let ct_k1 = cks.encrypt_u64_for_prince(k1);
    ///
    /// let d_message = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_message, &streams);
    /// let d_k0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_k0, &streams);
    /// let d_k1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_k1, &streams);
    ///
    /// let d_ct_res = sks.prince_encrypt(&d_message, &d_k0, &d_k1, num_prince_inputs, &streams);
    ///
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// let fhe_results = cks.decrypt_u64_from_prince(&ct_res, num_prince_inputs);
    ///
    /// assert_eq!(fhe_results, vec![0x603cd95fa72a8704]);
    /// ```
    pub fn prince_encrypt(
        &self,
        input: &CudaUnsignedRadixCiphertext,
        k0: &CudaUnsignedRadixCiphertext,
        k1: &CudaUnsignedRadixCiphertext,
        num_prince_inputs: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let keys = self.prince_encrypt_init(k0, k1, streams);
        self.prince_next(&keys, input, num_prince_inputs, streams)
    }

    /// Computes homomorphically `num_prince_inputs` PRINCEv2 decryptions: by
    /// alpha-reflection, the encryption circuit with swapped keys and
    /// reflected constants. See [`Self::prince_encrypt`].
    pub fn prince_decrypt(
        &self,
        input: &CudaUnsignedRadixCiphertext,
        k0: &CudaUnsignedRadixCiphertext,
        k1: &CudaUnsignedRadixCiphertext,
        num_prince_inputs: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let keys = self.prince_decrypt_init(k0, k1, streams);
        self.prince_next(&keys, input, num_prince_inputs, streams)
    }

    /// Prepares the encryption key material once, so that repeated
    /// [`Self::prince_next`] calls at constant keys skip the key preparation.
    /// The prepared material is independent of the batch size.
    pub fn prince_encrypt_init(
        &self,
        k0: &CudaUnsignedRadixCiphertext,
        k1: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaPrinceKeys {
        self.prince_init(k0, k1, false, streams)
    }

    /// Prepares the decryption key material once. See
    /// [`Self::prince_encrypt_init`].
    pub fn prince_decrypt_init(
        &self,
        k0: &CudaUnsignedRadixCiphertext,
        k1: &CudaUnsignedRadixCiphertext,
        streams: &CudaStreams,
    ) -> CudaPrinceKeys {
        self.prince_init(k0, k1, true, streams)
    }

    fn prince_init(
        &self,
        k0: &CudaUnsignedRadixCiphertext,
        k1: &CudaUnsignedRadixCiphertext,
        is_decrypt: bool,
        streams: &CudaStreams,
    ) -> CudaPrinceKeys {
        assert_eq!(
            (self.message_modulus.0, self.carry_modulus.0),
            (4, 4),
            "PRINCE requires 2_2 parameters (message_modulus = carry_modulus = 4)"
        );
        let max_degree = self.message_modulus.0 - 1;
        for (name, key) in [("k0", k0), ("k1", k1)] {
            assert_eq!(
                key.as_ref().d_blocks.lwe_ciphertext_count().0,
                NUM_U2_BLOCKS,
                "PRINCE {name} must contain {NUM_U2_BLOCKS} blocks, but contains {}",
                key.as_ref().d_blocks.lwe_ciphertext_count().0
            );
            assert!(
                key.as_ref()
                    .info
                    .blocks
                    .iter()
                    .all(|b| b.noise_level <= NoiseLevel::NOMINAL && b.degree.0 <= max_degree),
                "PRINCE {name} blocks must be fresh encryptions (nominal noise, degree <= {max_degree})"
            );
        }

        let size = self.get_prince_key_prep_size_on_gpu(streams);
        check_valid_cuda_malloc_assert_oom(size, streams.gpu_indexes[0]);

        let mut keys = CudaPrinceKeys {
            k0: k0.duplicate(streams),
            k1: k1.duplicate(streams),
            key_bits_first: self.create_trivial_zero_radix(NUM_BITS, streams),
            key_bits_second: self.create_trivial_zero_radix(NUM_BITS, streams),
            kap_bw_first: self.create_trivial_zero_radix(NUM_BITS, streams),
            kap_bw_second: self.create_trivial_zero_radix(NUM_BITS, streams),
            kap_mid_first: self.create_trivial_zero_radix(NUM_BITS, streams),
            is_decrypt,
        };

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_prince_key_prep(
                        streams,
                        keys.key_bits_first.as_mut(),
                        keys.key_bits_second.as_mut(),
                        keys.kap_bw_first.as_mut(),
                        keys.kap_bw_second.as_mut(),
                        keys.kap_mid_first.as_mut(),
                        k0.as_ref(),
                        k1.as_ref(),
                        is_decrypt,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_prince_key_prep(
                        streams,
                        keys.key_bits_first.as_mut(),
                        keys.key_bits_second.as_mut(),
                        keys.kap_bw_first.as_mut(),
                        keys.kap_bw_second.as_mut(),
                        keys.kap_mid_first.as_mut(),
                        k0.as_ref(),
                        k1.as_ref(),
                        is_decrypt,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        None,
                    );
                }
            }
        }
        keys
    }

    /// Runs the PRINCEv2 circuit on a batch with prepared key material, in the
    /// direction the keys were prepared for. Same constraints as
    /// [`Self::prince_encrypt`].
    pub fn prince_next(
        &self,
        keys: &CudaPrinceKeys,
        input: &CudaUnsignedRadixCiphertext,
        num_prince_inputs: usize,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        assert!(
            num_prince_inputs >= 1,
            "PRINCE num_prince_inputs must be at least 1"
        );
        assert_eq!(
            input.as_ref().d_blocks.lwe_ciphertext_count().0,
            num_prince_inputs * NUM_U2_BLOCKS,
            "PRINCE input must contain {} blocks for {num_prince_inputs} inputs, but contains {}",
            num_prince_inputs * NUM_U2_BLOCKS,
            input.as_ref().d_blocks.lwe_ciphertext_count().0
        );
        let max_degree = self.message_modulus.0 - 1;
        assert!(
            input
                .as_ref()
                .info
                .blocks
                .iter()
                .all(|b| b.noise_level <= NoiseLevel::NOMINAL && b.degree.0 <= max_degree),
            "PRINCE input blocks must be fresh encryptions (nominal noise, degree <= {max_degree})"
        );

        let size = self.get_prince_size_on_gpu(num_prince_inputs, keys.is_decrypt, streams);
        check_valid_cuda_malloc_assert_oom(size, streams.gpu_indexes[0]);

        let mut result: CudaUnsignedRadixCiphertext =
            self.create_trivial_zero_radix(num_prince_inputs * NUM_U2_BLOCKS, streams);

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        unsafe {
            match &self.bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_prince(
                        streams,
                        result.as_mut(),
                        input.as_ref(),
                        keys.k0.as_ref(),
                        keys.k1.as_ref(),
                        keys.key_bits_first.as_ref(),
                        keys.key_bits_second.as_ref(),
                        keys.kap_bw_first.as_ref(),
                        keys.kap_bw_second.as_ref(),
                        keys.kap_mid_first.as_ref(),
                        num_prince_inputs as u32,
                        keys.is_decrypt,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_bsk,
                        computing_ks_key.params_ffi(),
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                    cuda_backend_prince(
                        streams,
                        result.as_mut(),
                        input.as_ref(),
                        keys.k0.as_ref(),
                        keys.k1.as_ref(),
                        keys.key_bits_first.as_ref(),
                        keys.key_bits_second.as_ref(),
                        keys.kap_bw_first.as_ref(),
                        keys.kap_bw_second.as_ref(),
                        keys.kap_mid_first.as_ref(),
                        num_prince_inputs as u32,
                        keys.is_decrypt,
                        &d_multibit_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        self.message_modulus,
                        self.carry_modulus,
                        d_multibit_bsk,
                        computing_ks_key.params_ffi(),
                        None,
                    );
                }
            }
        }
        result
    }

    /// GPU memory the one-off key preparation needs. Independent of the batch
    /// size and of the direction.
    pub fn get_prince_key_prep_size_on_gpu(&self, streams: &CudaStreams) -> u64 {
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_prince_key_prep_size_on_gpu(
                streams,
                self.message_modulus,
                self.carry_modulus,
                d_bsk,
                computing_ks_key.params_ffi(),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_backend_get_prince_key_prep_size_on_gpu(
                    streams,
                    self.message_modulus,
                    self.carry_modulus,
                    d_multibit_bsk,
                    computing_ks_key.params_ffi(),
                    None,
                )
            }
        }
    }

    pub fn get_prince_encrypt_size_on_gpu(
        &self,
        num_prince_inputs: usize,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_prince_size_on_gpu(num_prince_inputs, false, streams)
    }

    pub fn get_prince_decrypt_size_on_gpu(
        &self,
        num_prince_inputs: usize,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_prince_size_on_gpu(num_prince_inputs, true, streams)
    }

    fn get_prince_size_on_gpu(
        &self,
        num_prince_inputs: usize,
        is_decrypt: bool,
        streams: &CudaStreams,
    ) -> u64 {
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &self.key_switching_key else {
            panic!("Only the standard atomic pattern is supported on GPU")
        };

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_prince_size_on_gpu(
                streams,
                num_prince_inputs as u32,
                is_decrypt,
                self.message_modulus,
                self.carry_modulus,
                d_bsk,
                computing_ks_key.params_ffi(),
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => cuda_backend_get_prince_size_on_gpu(
                streams,
                num_prince_inputs as u32,
                is_decrypt,
                self.message_modulus,
                self.carry_modulus,
                d_multibit_bsk,
                computing_ks_key.params_ffi(),
                None,
            ),
        }
    }
}
