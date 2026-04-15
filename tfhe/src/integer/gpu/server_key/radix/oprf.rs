use std::borrow::Borrow;

use crate::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{
    CudaBootstrappingKey, CudaDynamicKeyswitchingKey, CudaServerKey,
};
use itertools::Itertools;

use crate::core_crypto::prelude::{LweBskGroupingFactor, LweCiphertextCount};

use crate::shortint::oprf::{
    create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe, ExpandedOprfServerKey,
};
use crate::shortint::OprfSeed;

use crate::core_crypto::gpu::vec::CudaVec;
use crate::integer::block_decomposition::BlockDecomposer;
use crate::integer::gpu::{
    cuda_backend_get_grouped_oprf_size_on_gpu, cuda_backend_grouped_oprf,
    cuda_backend_grouped_oprf_custom_range, PBSType,
};

pub struct GenericCudaOprfServerKey<K> {
    bootstrapping_key: K,
}

pub type CudaOprfServerKey = GenericCudaOprfServerKey<CudaBootstrappingKey<u64>>;
pub type CudaOprfServerKeyView<'a> = GenericCudaOprfServerKey<&'a CudaBootstrappingKey<u64>>;

impl CudaOprfServerKey {
    pub fn as_view(&self) -> CudaOprfServerKeyView<'_> {
        GenericCudaOprfServerKey {
            bootstrapping_key: &self.bootstrapping_key,
        }
    }

    pub fn decompress_from_cpu(
        cpu_key: &crate::integer::oprf::CompressedOprfServerKey,
        streams: &CudaStreams,
    ) -> Self {
        let expanded = cpu_key.expand();
        Self {
            bootstrapping_key: CudaBootstrappingKey::from_expanded_oprf_server_key(
                &expanded.0,
                streams,
            )
            .unwrap(),
        }
    }

    pub fn from_expanded_cpu(expanded: &ExpandedOprfServerKey, streams: &CudaStreams) -> Self {
        let bootstrapping_key = match &expanded.0 {
            crate::shortint::oprf::ExpandedOprfBootstrappingKey::Classic { bsk, .. } => {
                let d_bootstrap_key =
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(bsk, None, streams);
                CudaBootstrappingKey::Classic(d_bootstrap_key)
            }
            crate::shortint::oprf::ExpandedOprfBootstrappingKey::MultiBit {
                bsk,
                thread_count: _,
                deterministic_execution: _,
            } => {
                let d_bootstrap_key =
                    CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(bsk, streams);
                CudaBootstrappingKey::MultiBit(d_bootstrap_key)
            }
        };
        Self { bootstrapping_key }
    }
}

impl<'a> CudaOprfServerKeyView<'a> {
    pub fn from_borrowed_bsk(bsk: &'a CudaBootstrappingKey<u64>) -> Self {
        Self {
            bootstrapping_key: bsk,
        }
    }
}

impl<K> GenericCudaOprfServerKey<K>
where
    K: Borrow<CudaBootstrappingKey<u64>>,
{
    fn assert_compatible_with_target_bsk(&self, target_bsk: &CudaBootstrappingKey<u64>) {
        assert_eq!(
            target_bsk.input_lwe_dimension(),
            self.bootstrapping_key.borrow().input_lwe_dimension()
        );
        assert_eq!(
            target_bsk.output_lwe_dimension(),
            self.bootstrapping_key.borrow().output_lwe_dimension()
        );
        assert_eq!(
            target_bsk.polynomial_size(),
            self.bootstrapping_key.borrow().polynomial_size()
        );
    }

    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::integer::gpu::CudaOprfServerKey;
    /// use tfhe::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let size = 4;
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// // Generate the OPRF key:
    /// let oprf_pk = OprfPrivateKey::new(&cks);
    /// let compressed_oprf_sk = CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
    /// let cuda_oprf_sk = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);
    ///
    /// let d_ct_res = cuda_oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer(&0u128.to_le_bytes(), size as u64, &sks, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert!(dec_result < 1 << (2 * size));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        self.generate_oblivious_pseudo_random_unbounded_integer(
            seed, num_blocks, target_sks, streams,
        )
    }

    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::integer::gpu::CudaOprfServerKey;
    /// use tfhe::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// // Generate the OPRF key:
    /// let oprf_pk = OprfPrivateKey::new(&cks);
    /// let compressed_oprf_sk = CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
    /// let cuda_oprf_sk = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);
    ///
    /// let random_bits_count = 3;
    ///
    /// let d_ct_res = cuda_oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
    ///     &0u128.to_le_bytes(),
    ///     random_bits_count,
    ///     size as u64,
    ///     &sks,
    ///     &streams,
    /// );
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt_radix(&ct_res);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;
        let range_log_size = message_bits_count * num_blocks;

        assert!(
                random_bits_count <= range_log_size,
                "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, 2^{range_log_size}[",
            );

        self.generate_oblivious_pseudo_random_bounded_integer(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
            streams,
        )
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::integer::gpu::CudaOprfServerKey;
    /// use tfhe::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// // Generate the OPRF key:
    /// let oprf_pk = OprfPrivateKey::new(&cks);
    /// let compressed_oprf_sk = CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
    /// let cuda_oprf_sk = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);
    ///
    /// let d_ct_res = cuda_oprf_sk.par_generate_oblivious_pseudo_random_signed_integer(&0u128.to_le_bytes(), size as u64, &sks, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed_radix(&ct_res);
    /// assert!(dec_result < 1 << (2 * size - 1));
    /// assert!(dec_result >= -(1 << (2 * size - 1)));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext {
        self.generate_oblivious_pseudo_random_unbounded_integer(
            seed, num_blocks, target_sks, streams,
        )
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::integer::gpu::CudaOprfServerKey;
    /// use tfhe::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// // Generate the OPRF key:
    /// let oprf_pk = OprfPrivateKey::new(&cks);
    /// let compressed_oprf_sk = CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
    /// let cuda_oprf_sk = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);
    ///
    /// let random_bits_count = 3;
    ///
    /// let d_ct_res = cuda_oprf_sk.par_generate_oblivious_pseudo_random_signed_integer_bounded(
    ///     &0u128.to_le_bytes(),
    ///     random_bits_count,
    ///     size as u64,
    ///     &sks,
    ///     &streams,
    /// );
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed_radix(&ct_res);
    /// assert!(dec_result >= 0);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer_bounded(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext {
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;
        let range_log_size = message_bits_count * num_blocks;

        #[allow(clippy::int_plus_one)]
        {
            assert!(
                random_bits_count + 1 <= range_log_size,
                "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                random_bits_count, range_log_size - 1, range_log_size - 1,
            );
        }

        self.generate_oblivious_pseudo_random_bounded_integer(
            seed,
            random_bits_count,
            num_blocks,
            target_sks,
            streams,
        )
    }

    // Generic interface to generate a single-block oblivious pseudo-random integer.
    // It performs checks specific to single-block capacity.
    //
    pub fn generate_oblivious_pseudo_random<T>(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(
            1 << random_bits_count <= target_sks.message_modulus.0,
            "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, {}[",
            target_sks.message_modulus.0
        );
        let carry_bits_count = target_sks.carry_modulus.0.ilog2() as u64;
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;
        assert!(
            random_bits_count <= carry_bits_count + message_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than carry_bits_count (={carry_bits_count}) + message_bits_count(={message_bits_count})",
        );

        self.generate_oblivious_pseudo_random_bounded_integer(
            seed,
            random_bits_count,
            1,
            target_sks,
            streams,
        )
    }

    // Generic internal implementation for unbounded pseudo-random generation.
    // It calls the core implementation with parameters for the unbounded case.
    //
    fn generate_oblivious_pseudo_random_unbounded_integer<T>(
        &self,
        seed: impl OprfSeed,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(target_sks.message_modulus.0.is_power_of_two());

        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;

        let mut result = target_sks.create_trivial_zero_radix(num_blocks as usize, streams);

        if num_blocks == 0 {
            return result;
        }

        self.generate_multiblocks_oblivious_pseudo_random(
            result.as_mut(),
            seed,
            num_blocks,
            num_blocks * message_bits_count,
            target_sks,
            streams,
        );

        result
    }

    // Generic internal implementation for bounded pseudo-random generation.
    // It calls the core implementation with parameters for the bounded case.
    //
    fn generate_oblivious_pseudo_random_bounded_integer<T>(
        &self,
        seed: impl OprfSeed,
        random_bits_count: u64,
        num_blocks: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(target_sks.message_modulus.0.is_power_of_two());
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;
        let num_active_blocks = random_bits_count.div_ceil(message_bits_count);

        let mut result = target_sks.create_trivial_zero_radix(num_blocks as usize, streams);

        assert!(
            num_blocks >= num_active_blocks,
            "Cuda error: num_blocks should be greater than num_blocks_to_process"
        );
        if num_active_blocks == 0 {
            return result;
        }

        self.generate_multiblocks_oblivious_pseudo_random(
            result.as_mut(),
            seed,
            num_active_blocks,
            random_bits_count,
            target_sks,
            streams,
        );
        result
    }

    // Core private implementation that calls the OPRF backend.
    // This function contains the main logic for both bounded and unbounded generation.
    //
    fn generate_multiblocks_oblivious_pseudo_random(
        &self,
        result: &mut CudaRadixCiphertext,
        seed: impl OprfSeed,
        num_active_blocks: u64,
        total_random_bits: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) {
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &target_sks.key_switching_key
        else {
            panic!("Only the standard atomic pattern is supported");
        };

        self.assert_compatible_with_target_bsk(&target_sks.bootstrapping_key);

        let bootstrapping_key = self.bootstrapping_key.borrow();
        let input_lwe_dimension = bootstrapping_key.input_lwe_dimension();
        let polynomial_size = bootstrapping_key.polynomial_size();
        let in_lwe_size = input_lwe_dimension.to_lwe_size();

        let h_seeded_lwe_list: Vec<u64> = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            LweCiphertextCount(num_active_blocks as usize),
        )
        .into_iter()
        .flat_map(|seeded| {
            raw_seeded_msed_to_lwe(&seeded, target_sks.ciphertext_modulus).into_container()
        })
        .collect();

        let mut d_seeded_lwe_input =
            unsafe { CudaVec::<u64>::new_async(h_seeded_lwe_list.len(), streams, 0) };
        unsafe {
            d_seeded_lwe_input.copy_from_cpu_async(&h_seeded_lwe_list, streams, 0);
        }

        let message_bits_count = target_sks.message_modulus.0.ilog2();

        unsafe {
            match bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_grouped_oprf(
                        streams,
                        result,
                        &d_seeded_lwe_input,
                        num_active_blocks as u32,
                        &d_bsk.d_vec,
                        d_bsk.input_lwe_dimension,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        target_sks.message_modulus,
                        target_sks.carry_modulus,
                        PBSType::Classical,
                        message_bits_count,
                        total_random_bits as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_bsk) => {
                    cuda_backend_grouped_oprf(
                        streams,
                        result,
                        &d_seeded_lwe_input,
                        num_active_blocks as u32,
                        &d_bsk.d_vec,
                        d_bsk.input_lwe_dimension,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        d_bsk.grouping_factor,
                        target_sks.message_modulus,
                        target_sks.carry_modulus,
                        PBSType::MultiBit,
                        message_bits_count,
                        total_random_bits as u32,
                        None,
                    );
                }
            }
        }
    }

    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range(
        &self,
        seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: u64,
        num_blocks_output: u64,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        assert!(
            target_sks.message_modulus.0.is_power_of_two(),
            "Message modulus must be a power of two"
        );
        let message_bits_count = target_sks.message_modulus.0.ilog2() as u64;

        assert!(
            !excluded_upper_bound.is_power_of_two(),
            "Use the cheaper par_generate_oblivious_pseudo_random_unsigned_integer_bounded function instead"
        );

        let num_bits_output = num_blocks_output * message_bits_count;
        assert!(
            (excluded_upper_bound as f64) < 2_f64.powi(num_bits_output as i32),
            "num_blocks_output(={num_blocks_output}) is too small to hold an integer up to excluded_upper_bound(={excluded_upper_bound})"
        );

        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &target_sks.key_switching_key
        else {
            panic!("Only the standard atomic pattern is supported");
        };

        self.assert_compatible_with_target_bsk(&target_sks.bootstrapping_key);

        let bootstrapping_key = self.bootstrapping_key.borrow();
        let input_lwe_dimension = bootstrapping_key.input_lwe_dimension();
        let polynomial_size = bootstrapping_key.polynomial_size();
        let in_lwe_size = input_lwe_dimension.to_lwe_size();

        let post_mul_num_bits =
            num_input_random_bits + (excluded_upper_bound as f64).log2().ceil() as u64;

        let num_blocks_intermediate = post_mul_num_bits.div_ceil(message_bits_count);

        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(excluded_upper_bound, 1).iter_as::<u8>();
        let mut has_at_least_one_set = vec![0u64; message_bits_count as usize];
        for (i, bit) in decomposer.collect_vec().iter().copied().enumerate() {
            if bit == 1 {
                has_at_least_one_set[i % message_bits_count as usize] = 1;
            }
        }
        let decomposed_scalar = BlockDecomposer::with_early_stop_at_zero(excluded_upper_bound, 1)
            .iter_as::<u64>()
            .collect::<Vec<_>>();

        let h_seeded_lwe_list: Vec<u64> = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size,
            LweCiphertextCount(num_blocks_intermediate as usize),
        )
        .into_iter()
        .flat_map(|seeded| {
            raw_seeded_msed_to_lwe(&seeded, target_sks.ciphertext_modulus).into_container()
        })
        .collect();

        let mut d_seeded_lwe_input =
            unsafe { CudaVec::<u64>::new_async(h_seeded_lwe_list.len(), streams, 0) };
        unsafe { d_seeded_lwe_input.copy_from_cpu_async(&h_seeded_lwe_list, streams, 0) };
        streams.synchronize();

        let mut result: CudaUnsignedRadixCiphertext =
            target_sks.create_trivial_zero_radix(num_blocks_output as usize, streams);

        unsafe {
            match bootstrapping_key {
                CudaBootstrappingKey::Classic(d_bsk) => {
                    cuda_backend_grouped_oprf_custom_range(
                        streams,
                        result.as_mut(),
                        num_blocks_intermediate as u32,
                        &d_seeded_lwe_input,
                        decomposed_scalar.as_slice(),
                        has_at_least_one_set.as_slice(),
                        num_input_random_bits as u32,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.input_lwe_dimension,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        LweBskGroupingFactor(0),
                        target_sks.message_modulus,
                        target_sks.carry_modulus,
                        PBSType::Classical,
                        message_bits_count as u32,
                        post_mul_num_bits as u32,
                        d_bsk.ms_noise_reduction_configuration.as_ref(),
                    );
                }
                CudaBootstrappingKey::MultiBit(d_bsk) => {
                    cuda_backend_grouped_oprf_custom_range(
                        streams,
                        result.as_mut(),
                        num_blocks_intermediate as u32,
                        &d_seeded_lwe_input,
                        decomposed_scalar.as_slice(),
                        has_at_least_one_set.as_slice(),
                        num_input_random_bits as u32,
                        &d_bsk.d_vec,
                        &computing_ks_key.d_vec,
                        d_bsk.input_lwe_dimension,
                        d_bsk.glwe_dimension,
                        d_bsk.polynomial_size,
                        computing_ks_key.decomposition_level_count(),
                        computing_ks_key.decomposition_base_log(),
                        d_bsk.decomp_level_count,
                        d_bsk.decomp_base_log,
                        d_bsk.grouping_factor,
                        target_sks.message_modulus,
                        target_sks.carry_modulus,
                        PBSType::MultiBit,
                        message_bits_count as u32,
                        post_mul_num_bits as u32,
                        None,
                    );
                }
            }
        }

        result
    }

    // Getter for the GPU memory usage of OPRF.
    //
    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
        &self,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> u64 {
        let message_bits = target_sks.message_modulus.0.ilog2();
        let CudaDynamicKeyswitchingKey::Standard(computing_ks_key) = &target_sks.key_switching_key
        else {
            panic!("Only the standard atomic pattern is supported");
        };

        match &self.bootstrapping_key.borrow() {
            CudaBootstrappingKey::Classic(d_bsk) => cuda_backend_get_grouped_oprf_size_on_gpu(
                streams,
                1,
                d_bsk.input_lwe_dimension,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                computing_ks_key.decomposition_level_count(),
                computing_ks_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                LweBskGroupingFactor(0),
                target_sks.message_modulus,
                target_sks.carry_modulus,
                PBSType::Classical,
                message_bits,
                message_bits,
                d_bsk.ms_noise_reduction_configuration.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_bsk) => cuda_backend_get_grouped_oprf_size_on_gpu(
                streams,
                1,
                d_bsk.input_lwe_dimension,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                computing_ks_key.decomposition_level_count(),
                computing_ks_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                d_bsk.grouping_factor,
                target_sks.message_modulus,
                target_sks.carry_modulus,
                PBSType::MultiBit,
                message_bits,
                message_bits,
                None,
            ),
        }
    }

    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
        &self,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
            target_sks, streams,
        )
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(
        &self,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
            target_sks, streams,
        )
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_bounded_size_on_gpu(
        &self,
        target_sks: &CudaServerKey,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
            target_sks, streams,
        )
    }
}
