use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaRadixCiphertext, CudaSignedRadixCiphertext,
    CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::{DefaultRandomGenerator, LweBskGroupingFactor};

use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};

pub use tfhe_csprng::seeders::{Seed, Seeder};

use crate::integer::gpu::{get_grouped_oprf_size_on_gpu, grouped_oprf_async, CudaVec, PBSType};

impl CudaServerKey {
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encryted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let d_ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_integer(Seed(0), size as u64, &streams);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert!(dec_result < 1 << (2 * size));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
        &self,
        seed: Seed,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let result = unsafe {
            self.generate_oblivious_pseudo_random_unbounded_integer_async(seed, num_blocks, streams)
        };
        streams.synchronize();
        result
    }

    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encryted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::Seed;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let random_bits_count = 3;
    ///
    /// let d_ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    ///     &streams,
    /// );
    /// let ct_res = d_ct_res.to_radix_ciphertext(&streams);
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt_radix(&ct_res);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
        &self,
        seed: Seed,
        random_bits_count: u64,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> CudaUnsignedRadixCiphertext {
        let result = unsafe {
            let message_bits_count = self.message_modulus.0.ilog2() as u64;
            let range_log_size = message_bits_count * num_blocks;

            assert!(
                random_bits_count <= range_log_size,
                "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, 2^{range_log_size}[",
            );

            self.generate_oblivious_pseudo_random_bounded_integer_async(
                seed,
                random_bits_count,
                num_blocks,
                streams,
            )
        };
        streams.synchronize();
        result
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encryted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::Seed;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let d_ct_res = sks.par_generate_oblivious_pseudo_random_signed_integer(Seed(0), size as u64, &streams);
    /// let ct_res = d_ct_res.to_signed_radix_ciphertext(&streams);
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed_radix(&ct_res);
    /// assert!(dec_result < 1 << (2 * size - 1));
    /// assert!(dec_result >= -(1 << (2 * size - 1)));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: Seed,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext {
        let result = unsafe {
            self.generate_oblivious_pseudo_random_unbounded_integer_async(seed, num_blocks, streams)
        };
        streams.synchronize();
        result
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encryted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::CudaStreams;
    /// use tfhe::core_crypto::gpu::vec::GpuIndex;
    /// use tfhe::integer::gpu::gen_keys_gpu;
    /// use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::Seed;
    ///
    /// let gpu_index = 0;
    /// let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_gpu(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    ///
    /// let random_bits_count = 3;
    ///
    /// let d_ct_res = sks.par_generate_oblivious_pseudo_random_signed_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
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
        seed: Seed,
        random_bits_count: u64,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> CudaSignedRadixCiphertext {
        let result = unsafe {
            let message_bits_count = self.message_modulus.0.ilog2() as u64;
            let range_log_size = message_bits_count * num_blocks;

            #[allow(clippy::int_plus_one)]
            {
                assert!(
                    random_bits_count + 1 <= range_log_size,
                    "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                    random_bits_count, range_log_size - 1, range_log_size - 1,
                );
            }

            self.generate_oblivious_pseudo_random_bounded_integer_async(
                seed,
                random_bits_count,
                num_blocks,
                streams,
            )
        };
        streams.synchronize();
        result
    }

    // Generic interface to generate a single-block oblivious pseudo-random integer.
    // It performs checks specific to single-block capacity.
    //
    pub fn generate_oblivious_pseudo_random<T>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(
            1 << random_bits_count <= self.message_modulus.0,
            "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, {}[",
            self.message_modulus.0
        );
        let carry_bits_count = self.carry_modulus.0.ilog2() as u64;
        let message_bits_count = self.message_modulus.0.ilog2() as u64;
        assert!(
            random_bits_count <= carry_bits_count + message_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than carry_bits_count (={carry_bits_count}) + message_bits_count(={message_bits_count})",
        );

        let result = unsafe {
            self.generate_oblivious_pseudo_random_bounded_integer_async(
                seed,
                random_bits_count,
                1,
                streams,
            )
        };
        streams.synchronize();
        result
    }

    // Generic internal implementation for unbounded pseudo-random generation.
    // It calls the core implementation with parameters for the unbounded case.
    //
    unsafe fn generate_oblivious_pseudo_random_unbounded_integer_async<T>(
        &self,
        seed: Seed,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(self.message_modulus.0.is_power_of_two());

        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        let mut result = self.create_trivial_zero_radix(num_blocks as usize, streams);

        if num_blocks == 0 {
            return result;
        }

        self.generate_multiblocks_oblivious_pseudo_random_async(
            result.as_mut(),
            seed,
            num_blocks,
            num_blocks,
            num_blocks * message_bits_count,
            streams,
        );

        result
    }

    // Generic internal implementation for bounded pseudo-random generation.
    // It calls the core implementation with parameters for the bounded case.
    //
    unsafe fn generate_oblivious_pseudo_random_bounded_integer_async<T>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        num_blocks: u64,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(self.message_modulus.0.is_power_of_two());
        let message_bits_count = self.message_modulus.0.ilog2() as u64;
        let num_active_blocks = random_bits_count.div_ceil(message_bits_count);

        let mut result = self.create_trivial_zero_radix(num_blocks as usize, streams);

        if num_active_blocks == 0 {
            return result;
        }

        self.generate_multiblocks_oblivious_pseudo_random_async(
            result.as_mut(),
            seed,
            num_active_blocks,
            num_blocks,
            random_bits_count,
            streams,
        );
        result
    }

    // Core private implementation that calls the OPRF backend.
    // This function contains the main logic for both bounded and unbounded generation.
    //
    unsafe fn generate_multiblocks_oblivious_pseudo_random_async(
        &self,
        result: &mut CudaRadixCiphertext,
        seed: Seed,
        num_active_blocks: u64,
        num_blocks: u64,
        total_random_bits: u64,
        streams: &CudaStreams,
    ) {
        let (input_lwe_dimension, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                (d_bsk.input_lwe_dimension, d_bsk.polynomial_size)
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                (d_bsk.input_lwe_dimension, d_bsk.polynomial_size)
            }
        };
        let in_lwe_size = input_lwe_dimension.to_lwe_size();

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
        let seeds: Vec<Seed> = (0..num_active_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let h_seeded_lwe_list: Vec<u64> = seeds
            .into_iter()
            .flat_map(|seed| {
                raw_seeded_msed_to_lwe(
                    &create_random_from_seed_modulus_switched::<u64>(
                        seed,
                        in_lwe_size,
                        polynomial_size.to_blind_rotation_input_modulus_log(),
                    ),
                    self.ciphertext_modulus,
                )
                .into_container()
            })
            .collect();

        let mut d_seeded_lwe_input = CudaVec::<u64>::new_async(h_seeded_lwe_list.len(), streams, 0);
        d_seeded_lwe_input.copy_from_cpu_async(&h_seeded_lwe_list, streams, 0);

        let message_bits_count = self.message_modulus.0.ilog2();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                grouped_oprf_async(
                    streams,
                    result,
                    &d_seeded_lwe_input,
                    num_active_blocks as u32,
                    num_blocks as u32,
                    &d_bsk.d_vec,
                    d_bsk.input_lwe_dimension,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    LweBskGroupingFactor(0),
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::Classical,
                    message_bits_count,
                    total_random_bits as u32,
                    d_bsk.ms_noise_reduction.as_ref(),
                );
            }
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                grouped_oprf_async(
                    streams,
                    result,
                    &d_seeded_lwe_input,
                    num_active_blocks as u32,
                    num_blocks as u32,
                    &d_bsk.d_vec,
                    d_bsk.input_lwe_dimension,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    self.key_switching_key.decomposition_level_count(),
                    self.key_switching_key.decomposition_base_log(),
                    d_bsk.decomp_level_count,
                    d_bsk.decomp_base_log,
                    d_bsk.grouping_factor,
                    self.message_modulus,
                    self.carry_modulus,
                    PBSType::MultiBit,
                    message_bits_count,
                    total_random_bits as u32,
                    None,
                );
            }
        }
    }

    // Getter for the GPU memory usage of OPRF.
    //
    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        let message_bits = self.message_modulus.0.ilog2();

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_grouped_oprf_size_on_gpu(
                streams,
                1,
                1,
                d_bsk.input_lwe_dimension,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                LweBskGroupingFactor(0),
                self.message_modulus,
                self.carry_modulus,
                PBSType::Classical,
                message_bits,
                message_bits,
                d_bsk.ms_noise_reduction.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_bsk) => get_grouped_oprf_size_on_gpu(
                streams,
                1,
                1,
                d_bsk.input_lwe_dimension,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                self.key_switching_key.decomposition_level_count(),
                self.key_switching_key.decomposition_base_log(),
                d_bsk.decomp_level_count,
                d_bsk.decomp_base_log,
                d_bsk.grouping_factor,
                self.message_modulus,
                self.carry_modulus,
                PBSType::MultiBit,
                message_bits,
                message_bits,
                None,
            ),
        }
    }

    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_bounded_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
    use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::server_key::CudaBootstrappingKey;
    use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
    use crate::integer::{ClientKey, RadixCiphertext};
    use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use crate::shortint::oprf::{create_random_from_seed_modulus_switched, raw_seeded_msed_to_lwe};
    use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use rand::prelude::SliceRandom;
    use rand::Rng;
    use rayon::prelude::*;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;
    use tfhe_csprng::generators::DefaultRandomGenerator;
    use tfhe_csprng::seeders::{Seed, Seeder};

    fn square(a: f64) -> f64 {
        a * a
    }

    fn get_random_gpu_streams() -> CudaStreams {
        let num_gpus = get_number_of_gpus();
        assert_ne!(
            num_gpus, 0,
            "Cannot run GPU test, since no GPUs are available."
        );

        let mut gpu_indexes: Vec<GpuIndex> = (0..num_gpus).map(GpuIndex::new).collect();

        let mut rng = rand::thread_rng();
        gpu_indexes.shuffle(&mut rng);

        let num_gpus_to_use = rng.gen_range(1..=num_gpus as usize);

        let random_slice = &gpu_indexes[..num_gpus_to_use];

        CudaStreams::new_multi_gpu_with_indexes(random_slice)
    }

    #[test]
    fn oprf_compare_plain_ci_run_filter() {
        let streams = get_random_gpu_streams();
        let (ck, gpu_sk) = gen_keys_gpu(
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            &streams,
        );

        for seed in 0..1000 {
            oprf_compare_plain_from_seed(Seed(seed), &ck, &gpu_sk, &streams);
        }
    }

    fn oprf_compare_plain_from_seed(
        seed: Seed,
        ck: &ClientKey,
        sk: &CudaServerKey,
        streams: &CudaStreams,
    ) {
        let params = ck.parameters();
        let num_blocks = 8;
        let message_bits_per_block = params.message_modulus().0.ilog2() as u64;
        let random_bits_count = num_blocks * message_bits_per_block;

        let input_p = 2 * params.polynomial_size().0 as u64;
        let log_input_p = input_p.ilog2();
        let p_prime = 1 << message_bits_per_block;
        let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;
        let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

        let d_img: CudaUnsignedRadixCiphertext = sk
            .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                seed,
                random_bits_count,
                num_blocks,
                streams,
            );
        let img: RadixCiphertext = d_img.to_radix_ciphertext(streams);

        let (lwe_size, polynomial_size) = match &sk.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => (
                d_bsk.input_lwe_dimension().to_lwe_size(),
                d_bsk.polynomial_size(),
            ),
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => (
                d_multibit_bsk.input_lwe_dimension().to_lwe_size(),
                d_multibit_bsk.polynomial_size(),
            ),
        };

        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        for i in 0..num_blocks as usize {
            let block_seed = seeder.seed();

            let ct = raw_seeded_msed_to_lwe(
                &create_random_from_seed_modulus_switched::<u64>(
                    block_seed,
                    lwe_size,
                    polynomial_size.to_blind_rotation_input_modulus_log(),
                ),
                sk.ciphertext_modulus,
            );

            let AtomicPatternClientKey::Standard(std_ck) = &ck.key.atomic_pattern else {
                panic!("Only std AP is supported on GPU")
            };

            let secret_key = std_ck.small_lwe_secret_key();
            let plain_prf_input = decrypt_lwe_ciphertext(&secret_key, &ct)
                .0
                .wrapping_add(1 << (64 - log_input_p - 1))
                >> (64 - log_input_p);

            let half_negacyclic_part = |x| 2 * (x / poly_delta) + 1;
            let negacyclic_part = |x| {
                assert!(x < input_p);
                if x < input_p / 2 {
                    half_negacyclic_part(x)
                } else {
                    2 * output_p - half_negacyclic_part(x - (input_p / 2))
                }
            };
            let prf = |x| {
                let a = (negacyclic_part(x) + p_prime - 1) % (2 * output_p);
                assert!(a % 2 == 0);
                a / 2
            };

            let expected_output = prf(plain_prf_input);

            let output = ck.key.decrypt_message_and_carry(&img.blocks[i]);

            assert!(output < p_prime);
            assert_eq!(output, expected_output);
        }
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;
        let streams = get_random_gpu_streams();
        let (ck, gpu_sk) = gen_keys_gpu(
            PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            &streams,
        );

        let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
            test_uniformity(sample_count, p_value_limit, distinct_values, f)
        };

        let random_bits_count = 2;

        test_uniformity(1 << random_bits_count, &|seed| {
            let d_img: CudaUnsignedRadixCiphertext = gpu_sk.generate_oblivious_pseudo_random(
                Seed(seed as u128),
                random_bits_count,
                &streams,
            );
            let img: RadixCiphertext = d_img.to_radix_ciphertext(&streams);
            ck.decrypt_radix(&img)
        });
    }

    pub fn test_uniformity<F>(sample_count: usize, p_value_limit: f64, distinct_values: u64, f: F)
    where
        F: Sync + Fn(usize) -> u64,
    {
        let p_value = uniformity_p_value(f, sample_count, distinct_values);

        assert!(
            p_value_limit < p_value,
            "p_value (={p_value}) expected to be bigger than {p_value_limit}"
        );
    }

    fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
    where
        F: Sync + Fn(usize) -> u64,
    {
        let values: Vec<_> = (0..sample_count).into_par_iter().map(&f).collect();

        let mut values_count = HashMap::new();

        for i in &values {
            assert!(*i < distinct_values, "i {} dv{}", *i, distinct_values);

            *values_count.entry(i).or_insert(0) += 1;
        }

        let single_expected_count = sample_count as f64 / distinct_values as f64;

        // https://en.wikipedia.org/wiki/Pearson's_chi-squared_test
        let distance: f64 = (0..distinct_values)
            .map(|value| *values_count.get(&value).unwrap_or(&0))
            .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
            .sum();

        statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
            .unwrap()
            .sf(distance)
    }
}
