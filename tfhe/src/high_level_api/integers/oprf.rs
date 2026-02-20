use super::{FheIntId, FheUint, FheUintId};
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::ReRandomizationMetadata;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::shortint::MessageModulus;
use crate::{FheInt, Seed};
use std::num::NonZeroU64;

impl<Id: FheUintId> FheUint<Id> {
    /// Generates an encrypted unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: Seed) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                        seed,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                        seed,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );

                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheUint8::get_generate_oblivious_pseudo_random_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_size_on_gpu(streams)
            } else {
                0
            }
        })
    }
    /// Generates an encrypted unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn generate_oblivious_pseudo_random_bounded(seed: Seed, random_bits_count: u64) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );
                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    /// Generates an encrypted unsigned integer
    /// taken almost uniformly in the given range using the given seed.
    /// Currently the range can only be in the form `[0, excluded_upper_bound[`
    /// with any `excluded_upper_bound` in `[1, 2^64[`.
    ///
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// This function guarantees the the norm-1 distance
    /// (defined as ∆(P,Q) := 1/2 Sum[ω∈Ω] |P(ω) − Q(ω)|)
    /// between the actual distribution and the target uniform distribution
    /// will be below the `max_distance` argument (which must be in ]0, 1[).
    /// The higher the distance, the more dissimilar the actual distribution is
    /// from the target uniform distribution.
    ///
    /// The default value for `max_distance` is `2^-128` if `None` is provided.
    ///
    /// Higher values allow better performance but must be considered carefully in the context of
    /// their target application as it may have serious unintended consequences.
    ///
    /// If the range is a power of 2, the distribution is uniform (for any `max_distance`) and
    /// the cost is smaller.
    ///
    /// ```rust
    /// use std::num::NonZeroU64;
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, RangeForRandom, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let excluded_upper_bound = NonZeroU64::new(3).unwrap();
    ///
    /// let range = RangeForRandom::new_from_excluded_upper_bound(excluded_upper_bound);
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random_custom_range(Seed(0), &range, None);
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < excluded_upper_bound.get() as u16);
    /// ```
    pub fn generate_oblivious_pseudo_random_custom_range(
        seed: Seed,
        range: &RangeForRandom,
        max_distance: Option<f64>,
    ) -> Self {
        let excluded_upper_bound = range.excluded_upper_bound;

        if excluded_upper_bound.is_power_of_two() {
            let random_bits_count = excluded_upper_bound.ilog2() as u64;

            Self::generate_oblivious_pseudo_random_bounded(seed, random_bits_count)
        } else {
            let max_distance = max_distance.unwrap_or_else(|| 2_f64.powi(-128));

            assert!(
                0_f64 < max_distance && max_distance < 1_f64,
                "max_distance (={max_distance}) should be in ]0, 1["
            );

            global_state::with_internal_keys(|key| match key {
                InternalServerKey::Cpu(key) => {
                    let message_modulus = key.message_modulus();

                    let num_input_random_bits = num_input_random_bits_for_max_distance(
                        excluded_upper_bound,
                        max_distance,
                        message_modulus,
                    );

                    let num_blocks_output = Id::num_blocks(key.message_modulus()) as u64;

                    let ct = key
                        .pbs_key()
                        .par_generate_oblivious_pseudo_random_unsigned_custom_range(
                            seed,
                            num_input_random_bits,
                            excluded_upper_bound,
                            num_blocks_output,
                        );

                    Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
                }
                #[cfg(feature = "gpu")]
                InternalServerKey::Cuda(cuda_key) => {
                    let message_modulus = cuda_key.message_modulus();

                    let num_input_random_bits = num_input_random_bits_for_max_distance(
                        excluded_upper_bound,
                        max_distance,
                        message_modulus,
                    );

                    let num_blocks_output = Id::num_blocks(cuda_key.message_modulus()) as u64;

                    let ct = cuda_key
                        .pbs_key()
                        .par_generate_oblivious_pseudo_random_unsigned_custom_range(
                            seed,
                            num_input_random_bits,
                            excluded_upper_bound.get(),
                            num_blocks_output,
                            &cuda_key.streams,
                        );

                    Self::new(ct, cuda_key.tag.clone(), ReRandomizationMetadata::default())
                }
                #[cfg(feature = "hpu")]
                InternalServerKey::Hpu(_device) => {
                    panic!("Hpu does not support this operation yet.")
                }
            })
        }
    }

    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random_bounded
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheUint8::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_bounded_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
                        streams,
                    )
            } else {
                0
            }
        })
    }
}

impl<Id: FheIntId> FheInt<Id> {
    /// Generates an encrypted signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let ct_res = FheInt8::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: i16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < 1 << 7);
    /// assert!(dec_result >= -(1 << 7));
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: Seed) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_signed_integer(
                        seed,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );
                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaSignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_signed_integer(
                        seed,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );

                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }

    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheInt8::get_generate_oblivious_pseudo_random_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_signed_integer_size_on_gpu(streams)
            } else {
                0
            }
        })
    }
    /// Generates an encrypted signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = FheInt8::generate_oblivious_pseudo_random_bounded(Seed(0), random_bits_count);
    ///
    /// let dec_result: i16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result >= 0);
    /// assert!(dec_result < 1 << random_bits_count);
    /// ```
    pub fn generate_oblivious_pseudo_random_bounded(seed: Seed, random_bits_count: u64) -> Self {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key
                    .pbs_key()
                    .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(key.message_modulus()) as u64,
                    );

                Self::new(ct, key.tag.clone(), ReRandomizationMetadata::default())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaSignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                        seed,
                        random_bits_count,
                        Id::num_blocks(cuda_key.message_modulus()) as u64,
                        streams,
                    );
                Self::new(
                    d_ct,
                    cuda_key.tag.clone(),
                    ReRandomizationMetadata::default(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support this operation yet.")
            }
        })
    }
    #[cfg(feature = "gpu")]
    /// Returns the amount of memory required to execute generate_oblivious_pseudo_random_bounded
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::check_valid_cuda_malloc_assert_oom;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt8, GpuIndex};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let size = FheInt8::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
    ///
    /// check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
    /// ```
    pub fn get_generate_oblivious_pseudo_random_bounded_size_on_gpu() -> u64 {
        global_state::with_internal_keys(|key| {
            if let InternalServerKey::Cuda(cuda_key) = key {
                let streams = &cuda_key.streams;
                cuda_key
                    .key
                    .key
                    .get_par_generate_oblivious_pseudo_random_unsigned_integer_bounded_size_on_gpu(
                        streams,
                    )
            } else {
                0
            }
        })
    }
}

pub struct RangeForRandom {
    excluded_upper_bound: NonZeroU64,
}

impl RangeForRandom {
    pub fn new_from_excluded_upper_bound(excluded_upper_bound: NonZeroU64) -> Self {
        Self {
            excluded_upper_bound,
        }
    }
}

fn num_input_random_bits_for_max_distance(
    excluded_upper_bound: NonZeroU64,
    max_distance: f64,
    message_modulus: MessageModulus,
) -> u64 {
    assert!(message_modulus.0.is_power_of_two());
    let log_message_modulus = message_modulus.0.ilog2() as u64;

    let mut random_block_count = 1;

    let random_block_count = loop {
        let random_bit_count = random_block_count * log_message_modulus;

        let distance = distance(excluded_upper_bound.get(), random_bit_count);

        if distance < max_distance {
            break random_block_count;
        }

        random_block_count += 1;
    };

    random_block_count * log_message_modulus
}

fn distance(excluded_upper_bound: u64, random_bit_count: u64) -> f64 {
    let remainder = mod_pow_2(random_bit_count, excluded_upper_bound);

    remainder as f64 * (excluded_upper_bound - remainder) as f64
        / (2_f64.powi(random_bit_count as i32) * excluded_upper_bound as f64)
}

// Computes 2^exponent % modulus
fn mod_pow_2(exponent: u64, modulus: u64) -> u64 {
    assert_ne!(modulus, 0);

    if modulus == 1 {
        return 0;
    }

    let mut result: u128 = 1;
    let mut base: u128 = 2; // We are calculating 2^i

    // We cast exponent to u128 to match the loop, though u64 is fine
    let mut exp = exponent;
    let mod_val = modulus as u128;

    while exp > 0 {
        // If exponent is odd, multiply result with base
        if exp % 2 == 1 {
            result = (result * base) % mod_val;
        }

        // Square the base
        base = (base * base) % mod_val;

        // Divide exponent by 2
        exp /= 2;
    }

    result as u64
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::integer::server_key::radix_parallel::tests_unsigned::test_oprf::{
        oprf_density_function, p_value_upper_bound_oprf_almost_uniformity_from_values,
        probability_density_function_from_density,
    };
    use crate::prelude::FheDecrypt;
    use crate::shortint::oprf::test::test_uniformity;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    use crate::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    const BASE_SAMPLE_COUNT: usize = 10_000;
    const P_VALUE_LIMIT: f64 = 0.001;
    // [0.7, 0.1] for `max_distance` chosen to have `num_input_random_bits` be [2, 4]
    // for any of the listed `excluded_upper_bound`
    const PRF_TEST_CASES: [(u64, f64, [u64; 4]); 2] =
        [(2, 0.7, [3, 5, 6, 7]), (4, 0.1, [3, 5, 6, 7])];

    // Helper: The "Oracle" implementation using BigInt
    // This is slow but mathematically guaranteed to be correct.
    fn oracle_mod_pow_2(exponent: u64, modulus: u64) -> u64 {
        assert_ne!(modulus, 0);

        if modulus == 1 {
            return 0;
        }

        let base = BigUint::from(2u32);
        let exp = BigUint::from(exponent);
        let modu = BigUint::from(modulus);

        let res = base.modpow(&exp, &modu);
        res.iter_u64_digits().next().unwrap_or(0)
    }

    #[test]
    fn test_edge_cases() {
        // 2^0 % 10 = 1
        assert_eq!(mod_pow_2(0, 10), 1, "Failed exponent 0");

        // 2^10 % 1 = 0
        assert_eq!(mod_pow_2(10, 1), 0, "Failed modulus 1");

        // 2^1 % 10 = 2
        assert_eq!(mod_pow_2(1, 10), 2, "Failed exponent 1");

        // 2^3 % 5 = 8 % 5 = 3
        assert_eq!(mod_pow_2(3, 5), 3, "Failed small calc");
    }

    #[test]
    fn test_boundaries_and_overflow() {
        assert_eq!(mod_pow_2(2, u64::MAX), 4);

        assert_eq!(mod_pow_2(u64::MAX, 3), 2);

        assert_eq!(mod_pow_2(5, 32), 0);
    }

    #[test]
    fn test_against_oracle() {
        let mut rng = thread_rng();
        for _ in 0..1_000_000 {
            let exp: u64 = rng.gen();
            let mod_val: u64 = rng.gen();

            let mod_val = if mod_val == 0 { 1 } else { mod_val };

            let expected = oracle_mod_pow_2(exp, mod_val);
            let actual = mod_pow_2(exp, mod_val);

            assert_eq!(
                actual, expected,
                "Mismatch! 2^{exp} % {mod_val} => Ours: {actual}, Oracle: {expected}",
            );
        }
    }

    #[test]
    fn test_distance_with_uniform() {
        for excluded_upper_bound in 1..20 {
            for num_input_random_bits in 0..20 {
                let density = oprf_density_function(excluded_upper_bound, num_input_random_bits);

                let theoretical_pdf = probability_density_function_from_density(&density);

                let p_uniform = 1. / excluded_upper_bound as f64;

                let actual_distance: f64 = 1. / 2.
                    * theoretical_pdf
                        .iter()
                        .map(|p| (*p - p_uniform).abs())
                        .sum::<f64>();

                let theoretical_distance = distance(excluded_upper_bound, num_input_random_bits);

                assert!(
                    (theoretical_distance - actual_distance).abs()
                        <= theoretical_distance / 1_000_000.,
                    "{theoretical_distance} != {actual_distance}"
                );
            }
        }
    }

    #[test]
    fn test_uniformity_scalar_mul_shift() {
        let max_distance = 2_f64.powi(-20);

        let message_modulus = MessageModulus(4);

        let excluded_upper_bound = 3;

        let num_input_random_bits = num_input_random_bits_for_max_distance(
            NonZeroU64::new(excluded_upper_bound).unwrap(),
            max_distance,
            message_modulus,
        );

        let sample_count: usize = 10_000_000;

        let p_value_limit: f64 = 0.001;

        // The distribution is not exactly uniform
        // This check ensures than with the given low max_distance,
        // the distribution is indistinguishable from the uniform with at the given sample count
        test_uniformity(sample_count, p_value_limit, excluded_upper_bound, |_seed| {
            oprf_clear_equivalent(excluded_upper_bound, num_input_random_bits)
        });
    }

    fn oprf_clear_equivalent(excluded_upper_bound: u64, num_input_random_bits: u64) -> u64 {
        let random_input_upper_bound = 1 << num_input_random_bits;

        let random_input = thread_rng().gen_range(0..random_input_upper_bound);

        (random_input * excluded_upper_bound) >> num_input_random_bits
    }

    #[test]
    fn test_uniformity_generate_oblivious_pseudo_random_custom_range_cpu() {
        let params = PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
        let config = ConfigBuilder::with_custom_parameters(params).build();
        let (cks, sks) = generate_keys(config);
        rayon::broadcast(|_| set_server_key(sks.clone()));
        let message_modulus = cks.message_modulus();

        for (expected_num_input_random_bits, max_distance, excluded_upper_bounds) in PRF_TEST_CASES
        {
            for excluded_upper_bound in excluded_upper_bounds {
                let sample_count = BASE_SAMPLE_COUNT * excluded_upper_bound as usize;

                let excluded_upper_bound = NonZeroU64::new(excluded_upper_bound).unwrap();

                let num_input_random_bits = num_input_random_bits_for_max_distance(
                    excluded_upper_bound,
                    max_distance,
                    message_modulus,
                );

                assert_eq!(num_input_random_bits, expected_num_input_random_bits);

                let num_input_random_bits = num_input_random_bits_for_max_distance(
                    excluded_upper_bound,
                    max_distance,
                    message_modulus,
                );

                let range = RangeForRandom::new_from_excluded_upper_bound(excluded_upper_bound);

                let real_values: Vec<u64> = (0..sample_count)
                    .into_par_iter()
                    .map(|_| {
                        let img = FheUint8::generate_oblivious_pseudo_random_custom_range(
                            Seed(rand::thread_rng().gen::<u128>()),
                            &range,
                            Some(max_distance),
                        );

                        img.decrypt(&cks)
                    })
                    .collect();

                let excluded_upper_bound = excluded_upper_bound.get();

                verify_output_distribution(
                    real_values,
                    sample_count,
                    num_input_random_bits,
                    excluded_upper_bound,
                    P_VALUE_LIMIT,
                );
            }
        }
    }

    fn verify_output_distribution(
        real_values: Vec<u64>,
        sample_count: usize,
        num_input_random_bits: u64,
        excluded_upper_bound: u64,
        p_value_limit: f64,
    ) {
        let uniform_values: Vec<u64> = (0..sample_count)
            .into_par_iter()
            .map(|_| thread_rng().gen_range(0..excluded_upper_bound))
            .collect();

        let clear_oprf_value_lower_num_input_random_bits = (0..sample_count)
            .into_par_iter()
            .map(|_| oprf_clear_equivalent(excluded_upper_bound, num_input_random_bits - 1))
            .collect();

        let clear_oprf_value_same_num_input_random_bits = (0..sample_count)
            .into_par_iter()
            .map(|_| oprf_clear_equivalent(excluded_upper_bound, num_input_random_bits))
            .collect();

        let clear_oprf_value_higher_num_input_random_bits = (0..sample_count)
            .into_par_iter()
            .map(|_| oprf_clear_equivalent(excluded_upper_bound, num_input_random_bits + 1))
            .collect();

        for (values, should_have_low_p_value) in [
            (real_values, false),
            // to test that the same distribution passes
            (clear_oprf_value_same_num_input_random_bits, false),
            // to test that other distribution don't pass
            // (makes sure the test is statistically powerful)
            (uniform_values, true),
            (clear_oprf_value_lower_num_input_random_bits, true),
            (clear_oprf_value_higher_num_input_random_bits, true),
        ] {
            let p_value_upper_bound = p_value_upper_bound_oprf_almost_uniformity_from_values(
                &values,
                num_input_random_bits,
                excluded_upper_bound,
            );

            println!("p_value_upper_bound: {p_value_upper_bound}");

            if should_have_low_p_value {
                assert!(
                    p_value_upper_bound < p_value_limit,
                    "p_value_upper_bound (={p_value_upper_bound}) expected to be smaller than {p_value_limit}"
                );
            } else {
                assert!(
                    p_value_limit < p_value_upper_bound,
                    "p_value_upper_bound (={p_value_upper_bound}) expected to be bigger than {p_value_limit}"
                );
            }
        }
    }

    #[cfg(feature = "gpu")]
    mod gpu {
        use super::*;
        use crate::core_crypto::gpu::get_number_of_gpus;
        use crate::prelude::check_valid_cuda_malloc_assert_oom;
        use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use crate::{
            unset_server_key, ClientKey, CompressedServerKey, FheInt128, FheUint32, FheUint64,
            GpuIndex,
        };
        use rayon::iter::IndexedParallelIterator;
        use rayon::prelude::{IntoParallelRefIterator, ParallelSlice};
        use rayon::ThreadPoolBuilder;

        #[test]
        fn test_oprf_gpu() {
            for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
                let _ck = setup_fn();
                let seed = Seed(0);

                let img = FheUint64::generate_oblivious_pseudo_random_bounded(seed, 1);

                assert_eq!(img.ciphertext.into_cpu().blocks.len(), 32);

                let img = FheInt128::generate_oblivious_pseudo_random_bounded(seed, 1);

                assert_eq!(img.ciphertext.into_cpu().blocks.len(), 64);
            }
        }

        #[test]
        fn test_oprf_size_on_gpu() {
            for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
                let _ck = setup_fn();
                let size = FheUint32::get_generate_oblivious_pseudo_random_bounded_size_on_gpu();
                check_valid_cuda_malloc_assert_oom(size, GpuIndex::new(0));
                let size_1 = FheUint64::get_generate_oblivious_pseudo_random_size_on_gpu();
                check_valid_cuda_malloc_assert_oom(size_1, GpuIndex::new(0));
            }
        }

        #[test]
        fn test_uniformity_generate_oblivious_pseudo_random_custom_range_gpu() {
            let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
            let config = ConfigBuilder::with_custom_parameters(params).build();
            let cks = ClientKey::generate(config);
            let message_modulus = cks.message_modulus();

            for (expected_num_input_random_bits, max_distance, excluded_upper_bounds) in
                PRF_TEST_CASES
            {
                for excluded_upper_bound in excluded_upper_bounds {
                    let sample_count = BASE_SAMPLE_COUNT * excluded_upper_bound as usize;

                    let excluded_upper_bound = NonZeroU64::new(excluded_upper_bound).unwrap();

                    let num_input_random_bits = num_input_random_bits_for_max_distance(
                        excluded_upper_bound,
                        max_distance,
                        message_modulus,
                    );

                    assert_eq!(num_input_random_bits, expected_num_input_random_bits);

                    let num_input_random_bits = num_input_random_bits_for_max_distance(
                        excluded_upper_bound,
                        max_distance,
                        message_modulus,
                    );

                    let range = RangeForRandom::new_from_excluded_upper_bound(excluded_upper_bound);

                    let num_gpus = get_number_of_gpus() as usize;

                    let compressed_sks = CompressedServerKey::new(&cks);
                    let sks_vec = (0..num_gpus)
                        .map(|i| compressed_sks.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
                        .collect::<Vec<_>>();

                    let idx: Vec<usize> = (0..sample_count).collect();
                    let pool = ThreadPoolBuilder::new()
                        .num_threads(8 * num_gpus)
                        .exit_handler(|_| unset_server_key())
                        .build()
                        .unwrap();
                    let real_values: Vec<u64> = pool.install(|| {
                        idx.par_chunks(sample_count / num_gpus)
                            .enumerate()
                            .flat_map(|(gpu_index, chunk)| {
                                // Note: gpu_index must be valid for sks_vec
                                let sks = sks_vec[gpu_index].clone();

                                chunk
                                    .par_iter()
                                    .map_init(
                                        move || {
                                            // runs once per Rayon worker thread used for this chunk
                                            set_server_key(sks.clone());
                                            rand::thread_rng()
                                        },
                                        |rng, _| {
                                            let img = FheUint8::generate_oblivious_pseudo_random_custom_range(
                                                Seed(rng.gen::<u128>()),
                                                &range,
                                                Some(max_distance),
                                            );
                                            img.decrypt(&cks)
                                        },
                                    )
                                    .collect::<Vec<u64>>()
                            })
                            .collect()
                    });

                    let excluded_upper_bound = excluded_upper_bound.get();

                    verify_output_distribution(
                        real_values,
                        sample_count,
                        num_input_random_bits,
                        excluded_upper_bound,
                        P_VALUE_LIMIT,
                    );
                }
            }
        }
    }
}
