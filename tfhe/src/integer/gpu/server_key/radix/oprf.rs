use crate::core_crypto::gpu::{
    get_programmable_bootstrap_multi_bit_size_on_gpu, get_programmable_bootstrap_size_on_gpu,
    CudaStreams,
};
use crate::integer::gpu::ciphertext::{
    CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext,
};
use crate::integer::gpu::server_key::{CudaBootstrappingKey, CudaServerKey};

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::shortint::oprf::create_random_from_seed_modulus_switched;
use crate::shortint::server_key::LookupTableOwned;

pub use tfhe_csprng::seeders::{Seed, Seeder};

use crate::core_crypto::gpu::{
    cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
    cuda_programmable_bootstrap_lwe_ciphertext,
};

use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::gpu::add_lwe_ciphertext_vector_plaintext_scalar_async;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::prelude::CastInto;
use crate::integer::gpu::server_key::radix::{CudaLweCiphertextList, LweCiphertextCount};
use crate::integer::gpu::CudaVec;
use itertools::Itertools;

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
        assert!(self.message_modulus.0.is_power_of_two());
        let range_log_size = self.message_modulus.0.ilog2() as u64 * num_blocks;

        let random_bits_count = range_log_size;

        assert!(self.message_modulus.0.is_power_of_two());
        let mut streams_vector = Vec::<CudaStreams>::with_capacity(num_blocks as usize);
        for _ in 0..num_blocks {
            streams_vector.push(CudaStreams::new_single_gpu(streams.gpu_indexes[0]));
        }

        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let stream_index = i;
                let i = i as u64;
                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2) block
                    // must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);
                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                top_message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    } else {
                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    }
                } else {
                    let ct: CudaUnsignedRadixCiphertext =
                        self.create_trivial_zero_radix(1, &streams_vector[stream_index]);
                    ct.ciphertext
                }
            })
            .collect::<Vec<_>>();
        self.convert_radixes_vec_to_single_radix_ciphertext(&blocks, streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => get_programmable_bootstrap_size_on_gpu(
                streams,
                d_bsk.input_lwe_dimension,
                d_bsk.glwe_dimension,
                d_bsk.polynomial_size,
                d_bsk.decomp_level_count,
                1,
                d_bsk.d_ms_noise_reduction_key.as_ref(),
            ),
            CudaBootstrappingKey::MultiBit(d_bsk) => {
                get_programmable_bootstrap_multi_bit_size_on_gpu(
                    streams,
                    d_bsk.glwe_dimension,
                    d_bsk.polynomial_size,
                    d_bsk.decomp_level_count,
                    1,
                )
            }
        }
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
        assert!(self.message_modulus.0.is_power_of_two());
        let range_log_size = self.message_modulus.0.ilog2() as u64 * num_blocks;

        assert!(
            random_bits_count <= range_log_size,
            "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, 2^{range_log_size}[",
        );

        assert!(self.message_modulus.0.is_power_of_two());
        let mut streams_vector = Vec::<CudaStreams>::with_capacity(num_blocks as usize);
        for _ in 0..num_blocks {
            streams_vector.push(CudaStreams::new_single_gpu(streams.gpu_indexes[0]));
        }
        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let stream_index = i;
                let i = i as u64;

                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2) block
                    // must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);

                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                top_message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    } else {
                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    }
                } else {
                    let ct: CudaUnsignedRadixCiphertext =
                        self.create_trivial_zero_radix(1, &streams_vector[stream_index]);
                    ct.ciphertext
                }
            })
            .collect::<Vec<_>>();
        self.convert_radixes_vec_to_single_radix_ciphertext(&blocks, streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
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
        assert!(self.message_modulus.0.is_power_of_two());
        let message_bits_count = self.message_modulus.0.ilog2() as u64;
        let mut streams_vector = Vec::<CudaStreams>::with_capacity(num_blocks as usize);
        for _ in 0..num_blocks {
            streams_vector.push(CudaStreams::new_single_gpu(streams.gpu_indexes[0]));
        }
        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let stream_index = i;
                let ct: CudaSignedRadixCiphertext = self.generate_oblivious_pseudo_random(
                    seed,
                    message_bits_count,
                    &streams_vector[stream_index],
                );
                ct.ciphertext
            })
            .collect::<Vec<_>>();
        self.convert_radixes_vec_to_single_radix_ciphertext(&blocks, streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
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
        assert!(self.message_modulus.0.is_power_of_two());
        let range_log_size = self.message_modulus.0.ilog2() as u64 * num_blocks;

        #[allow(clippy::int_plus_one)]
        {
            assert!(
                random_bits_count + 1 <= range_log_size,
                "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                random_bits_count, range_log_size-1, range_log_size-1,
            );
        }

        assert!(self.message_modulus.0.is_power_of_two());
        let mut streams_vector = Vec::<CudaStreams>::with_capacity(num_blocks as usize);
        for _ in 0..num_blocks {
            streams_vector.push(CudaStreams::new_single_gpu(streams.gpu_indexes[0]));
        }
        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds = (0..num_blocks).map(|_| deterministic_seeder.seed());

        let blocks = seeds
            .into_iter()
            .enumerate()
            .map(|(i, seed)| {
                let stream_index = i;
                let i = i as u64;
                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2)
                    // block must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);
                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                top_message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    } else {
                        let ct: CudaUnsignedRadixCiphertext = self
                            .generate_oblivious_pseudo_random(
                                seed,
                                message_bits_count,
                                &streams_vector[stream_index],
                            );
                        ct.ciphertext
                    }
                } else {
                    let ct: CudaUnsignedRadixCiphertext =
                        self.create_trivial_zero_radix(1, &streams_vector[stream_index]);
                    ct.ciphertext
                }
            })
            .collect::<Vec<_>>();

        self.convert_radixes_vec_to_single_radix_ciphertext(&blocks, streams)
    }

    pub fn get_par_generate_oblivious_pseudo_random_signed_integer_bounded_size_on_gpu(
        &self,
        streams: &CudaStreams,
    ) -> u64 {
        self.get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(streams)
    }
    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// `2^random_bits_count` must be smaller than the message modulus
    /// The encryted value is oblivious to the server
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
            "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [0, {}[",
            random_bits_count, self.message_modulus.0
        );
        self.generate_oblivious_pseudo_random_message_and_carry(seed, random_bits_count, streams)
    }

    /// Uniformly generates a random value in `[0, 2^random_bits_count[`
    /// The encryted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_message_and_carry<T>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(
            self.message_modulus.0.is_power_of_two(),
            "The message modulus(={}), must be a power of 2 to use the OPRF",
            self.message_modulus.0
        );
        let message_bits_count = self.message_modulus.0.ilog2() as u64;

        assert!(
            self.carry_modulus.0.is_power_of_two(),
            "The carry modulus(={}), must be a power of 2 to use the OPRF",
            self.carry_modulus.0
        );
        let carry_bits_count = self.carry_modulus.0.ilog2() as u64;

        assert!(
            random_bits_count <= carry_bits_count + message_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than carry_bits_count (={carry_bits_count}) + message_bits_count(={message_bits_count})",
        );
        self.generate_oblivious_pseudo_random_custom_encoding(
            seed,
            random_bits_count,
            1 + carry_bits_count + message_bits_count,
            streams,
        )
    }

    /// Uniformly generates a random encrypted value in `[0, 2^random_bits_count[`
    /// The output in in the form 0000rrr000noise (rbc=3, fbc=7)
    /// The encryted value is oblivious to the server
    pub(crate) fn generate_oblivious_pseudo_random_custom_encoding<T>(
        &self,
        seed: Seed,
        random_bits_count: u64,
        full_bits_count: u64,
        streams: &CudaStreams,
    ) -> T
    where
        T: CudaIntegerRadixCiphertext,
    {
        assert!(
            random_bits_count <= full_bits_count,
            "The number of random bits asked for (={random_bits_count}) is bigger than full_bits_count (={full_bits_count})"
        );

        let (in_lwe_size, out_lwe_dimension, polynomial_size) = match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => (
                d_bsk.input_lwe_dimension().to_lwe_size(),
                d_bsk.output_lwe_dimension(),
                d_bsk.polynomial_size(),
            ),
            CudaBootstrappingKey::MultiBit(d_bsk) => (
                d_bsk.input_lwe_dimension().to_lwe_size(),
                d_bsk.output_lwe_dimension(),
                d_bsk.polynomial_size(),
            ),
        };

        let seeded = create_random_from_seed_modulus_switched(
            seed,
            in_lwe_size,
            polynomial_size.to_blind_rotation_input_modulus_log(),
            self.ciphertext_modulus,
        );

        let p = 1 << random_bits_count;

        let delta = 1_u64 << (64 - full_bits_count);

        let poly_delta = 2 * polynomial_size.0 as u64 / p;

        let lut_no_encode: LookupTableOwned =
            self.generate_lookup_table_no_encode(|x| (2 * (x / poly_delta) + 1) * delta / 2);

        let num_ct_blocks = 1;
        let ct_seeded = CudaLweCiphertextList::from_lwe_ciphertext(&seeded, streams);

        let mut ct_out: T = self.create_trivial_zero_radix(num_ct_blocks, streams);

        let number_of_messages = 1;
        let d_accumulator =
            CudaGlweCiphertextList::from_glwe_ciphertext(&lut_no_encode.acc, streams);
        let mut lut_vector_indexes: Vec<u64> = vec![u64::ZERO; number_of_messages];
        for (i, ind) in lut_vector_indexes.iter_mut().enumerate() {
            *ind = <usize as CastInto<u64>>::cast_into(i);
        }

        let mut d_lut_vector_indexes =
            unsafe { CudaVec::<u64>::new_async(number_of_messages, streams, 0) };
        unsafe { d_lut_vector_indexes.copy_from_cpu_async(&lut_vector_indexes, streams, 0) };
        let lwe_indexes_usize: Vec<usize> = (0..num_ct_blocks).collect_vec();
        let lwe_indexes = lwe_indexes_usize
            .iter()
            .map(|&x| <usize as CastInto<u64>>::cast_into(x))
            .collect_vec();
        let mut d_output_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
        let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_ct_blocks, streams, 0) };
        unsafe {
            d_input_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
            d_output_indexes.copy_from_cpu_async(&lwe_indexes, streams, 0);
        }

        match &self.bootstrapping_key {
            CudaBootstrappingKey::Classic(d_bsk) => {
                cuda_programmable_bootstrap_lwe_ciphertext(
                    &ct_seeded,
                    &mut ct_out.as_mut().d_blocks,
                    &d_accumulator,
                    &d_lut_vector_indexes,
                    &d_output_indexes,
                    &d_input_indexes,
                    LweCiphertextCount(num_ct_blocks),
                    d_bsk,
                    streams,
                );
            }
            CudaBootstrappingKey::MultiBit(d_multibit_bsk) => {
                cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                    &ct_seeded,
                    &mut ct_out.as_mut().d_blocks,
                    &d_accumulator,
                    &d_lut_vector_indexes,
                    &d_output_indexes,
                    &d_input_indexes,
                    d_multibit_bsk,
                    streams,
                );
            }
        }

        let plaintext_to_add = (p - 1) * delta / 2;
        let ct_cloned = ct_out.duplicate(streams);
        unsafe {
            add_lwe_ciphertext_vector_plaintext_scalar_async(
                streams,
                &mut ct_out.as_mut().d_blocks.0.d_vec,
                &ct_cloned.as_ref().d_blocks.0.d_vec,
                plaintext_to_add,
                out_lwe_dimension,
                num_ct_blocks as u32,
            );
        }
        streams.synchronize();
        ct_out
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::core_crypto::prelude::decrypt_lwe_ciphertext;
    use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::server_key::CudaBootstrappingKey;
    use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
    use crate::integer::{ClientKey, RadixCiphertext};
    use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
    use crate::shortint::oprf::create_random_from_seed_modulus_switched;
    use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use rayon::prelude::*;
    use statrs::distribution::ContinuousCDF;
    use std::collections::HashMap;
    use tfhe_csprng::seeders::Seed;

    fn square(a: f64) -> f64 {
        a * a
    }

    #[test]
    fn oprf_compare_plain_ci_run_filter() {
        let gpu_index = 0;
        let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
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

        let random_bits_count = 2;

        let input_p = 2 * params.polynomial_size().0 as u64;

        let log_input_p = input_p.ilog2();

        let p_prime = 1 << random_bits_count;

        let output_p = 2 * params.carry_modulus().0 * params.message_modulus().0;

        let poly_delta = 2 * params.polynomial_size().0 as u64 / p_prime;

        let d_img: CudaUnsignedRadixCiphertext =
            sk.generate_oblivious_pseudo_random(seed, random_bits_count, streams);
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

        let ct = create_random_from_seed_modulus_switched(
            seed,
            lwe_size,
            polynomial_size.to_blind_rotation_input_modulus_log(),
            sk.ciphertext_modulus,
        );

        let AtomicPatternClientKey::Standard(std_ck) = &ck.key.atomic_pattern else {
            panic!("Only std AP is supported on GPU")
        };

        let sk = std_ck.small_lwe_secret_key();
        let plain_prf_input = decrypt_lwe_ciphertext(&sk, &ct)
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

        let output = ck.key.decrypt_message_and_carry(&img.blocks[0]);

        assert!(output < p_prime);
        assert_eq!(output, expected_output);
    }

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 100_000;

        let p_value_limit: f64 = 0.000_01;
        let gpu_index = 0;
        let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
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
            ck.key.decrypt_message_and_carry(&img.blocks[0])
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
