use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use crate::shortint::MessageModulus;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

pub use tfhe_csprng::seeders::{Seed, Seeder};

impl ServerKey {
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_integer(Seed(0), size as u64);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    ///
    /// assert!(dec_result < 1 << (2 * size));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
        &self,
        seed: Seed,
        num_blocks: u64,
    ) -> RadixCiphertext {
        assert!(self.message_modulus().0.is_power_of_two());
        let range_log_size = self.message_modulus().0.ilog2() as u64 * num_blocks;

        let random_bits_count = range_log_size;

        let sk = &self.key;

        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let i = i as u64;

                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2) block
                    // must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);

                        sk.generate_oblivious_pseudo_random(seed, top_message_bits_count)
                    } else {
                        sk.generate_oblivious_pseudo_random(seed, message_bits_count)
                    }
                } else {
                    self.key.create_trivial(0)
                }
            })
            .collect::<Vec<_>>();

        RadixCiphertext::from(blocks)
    }

    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
        &self,
        seed: Seed,
        random_bits_count: u64,
        num_blocks: u64,
    ) -> RadixCiphertext {
        assert!(self.message_modulus().0.is_power_of_two());
        let range_log_size = self.message_modulus().0.ilog2() as u64 * num_blocks;

        assert!(
            random_bits_count <= range_log_size,
            "The range asked for a random value (=[0, 2^{random_bits_count}[) does not fit in the available range [0, 2^{range_log_size}[", 
        );

        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let i = i as u64;

                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2) block
                    // must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);

                        self.key
                            .generate_oblivious_pseudo_random(seed, top_message_bits_count)
                    } else {
                        self.key
                            .generate_oblivious_pseudo_random(seed, message_bits_count)
                    }
                } else {
                    self.key.create_trivial(0)
                }
            })
            .collect::<Vec<_>>();

        RadixCiphertext::from(blocks)
    }

    /// Generates an encrypted `num_blocks_output` blocks unsigned integer
    /// taken almost uniformly in [0, excluded_upper_bound[ using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    /// The higher num_input_random_bits, the closer to a uniform the distribution will be (at the
    /// cost of computation time).
    /// It is recommended to use a multiple of `log2_message_modulus`
    /// as `num_input_random_bits`
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let num_input_random_bits = 5;
    /// let excluded_upper_bound = 3;
    /// let num_blocks_output = 8;
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_custom_range(
    ///     Seed(0),
    ///     num_input_random_bits,
    ///     excluded_upper_bound,
    ///     num_blocks_output,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    ///
    /// assert!(dec_result < excluded_upper_bound);
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range(
        &self,
        seed: Seed,
        num_input_random_bits: u64,
        excluded_upper_bound: u64,
        num_blocks_output: u64,
    ) -> RadixCiphertext {
        assert!(self.message_modulus().0.is_power_of_two());
        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        assert!(
            !excluded_upper_bound.is_power_of_two(),
            "Use the cheaper par_generate_oblivious_pseudo_random_unsigned_integer_bounded function instead"
        );

        let num_bits_output = num_blocks_output * message_bits_count;
        assert!((excluded_upper_bound as f64) < 2_f64.powi(num_bits_output as i32), "num_blocks_output(={num_blocks_output}) is too small to hold an integer up to excluded_upper_bound(=excluded_upper_bound)");

        let post_mul_num_bits =
            num_input_random_bits + (excluded_upper_bound as f64).log2().ceil() as u64;

        let num_blocks = post_mul_num_bits.div_ceil(message_bits_count);

        let random_input = self.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
            seed,
            num_input_random_bits,
            num_blocks,
        );

        let random_multiplied = self.scalar_mul_parallelized(&random_input, excluded_upper_bound);

        let mut result =
            self.scalar_right_shift_parallelized(&random_multiplied, num_input_random_bits);

        // Adjust the number of leading (MSB) trivial zeros blocks
        result
            .blocks
            .resize(num_blocks_output as usize, self.key.create_trivial(0));

        result
    }

    /// Generates an encrypted `num_blocks_output` blocks unsigned integer
    /// taken almost uniformly in `[0, excluded_upper_bound[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// The norm-1 distance (defined as ∆(, ) := 1/2 Sum[ω∈Ω] |P(ω) − Q(ω)| between the actual distribution and the target uniform distribution is below the `max_distance` argument.
    ///
    /// A safe value for `max_distance` is `2^-128`. It is the default value if None is provided.
    ///
    /// Higher values allow better performance but must be considered carefully in the context of their target application
    /// as it may have serious unintended consequences.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let excluded_upper_bound = 3;
    /// let num_blocks_output = 8;
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_custom_range2(Seed(0), excluded_upper_bound,num_blocks_output, None);
    ///
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert!(dec_result < excluded_upper_bound);
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_custom_range2(
        &self,
        seed: Seed,
        excluded_upper_bound: u64,
        num_blocks_output: u64,
        max_distance: Option<f64>,
    ) -> RadixCiphertext {
        let max_distance = max_distance.unwrap_or_else(|| 2_f64.powi(-128));

        let message_modulus = self.message_modulus();

        let num_input_random_bits = num_input_random_bits_for_max_distance(
            excluded_upper_bound,
            max_distance,
            message_modulus,
        );

        self.par_generate_oblivious_pseudo_random_unsigned_custom_range(
            seed,
            num_input_random_bits,
            excluded_upper_bound,
            num_blocks_output,
        )
    }
}

fn num_input_random_bits_for_max_distance(
    excluded_upper_bound: u64,
    max_distance: f64,
    message_modulus: MessageModulus,
) -> u64 {
    let log_message_modulus = message_modulus.0.ilog2() as u64;

    let mut random_block_count = 1;

    let random_block_count = loop {
        let random_bit_count = random_block_count * log_message_modulus;

        let distance = distance(excluded_upper_bound, random_bit_count);

        if distance < max_distance {
            break random_block_count;
        }

        random_block_count += 1;
    };

    random_block_count * log_message_modulus
}

fn distance(excluded_upper_bound: u64, random_bit_count: u64) -> f64 {
    let remainder = mod_pow_2(random_bit_count, excluded_upper_bound) as f64;

    remainder * (excluded_upper_bound as f64 - remainder)
        / (2_f64.powi(random_bit_count as i32) * excluded_upper_bound as f64)
}

// Computes 2^exponent % modulus
fn mod_pow_2(exponent: u64, modulus: u64) -> u64 {
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

impl ServerKey {
    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_signed_integer(Seed(0), size as u64);
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed(&ct_res);
    /// assert!(dec_result < 1 << (2 * size - 1));
    /// assert!(dec_result >= -(1 << (2 * size - 1)));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: Seed,
        num_blocks: u64,
    ) -> SignedRadixCiphertext {
        assert!(self.message_modulus().0.is_power_of_two());
        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .map(|seed| {
                self.key
                    .generate_oblivious_pseudo_random(seed, message_bits_count)
            })
            .collect::<Vec<_>>();

        SignedRadixCiphertext::from(blocks)
    }

    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// let random_bits_count = 3;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_signed_integer_bounded(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed(&ct_res);
    /// assert!(dec_result >= 0);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer_bounded(
        &self,
        seed: Seed,
        random_bits_count: u64,
        num_blocks: u64,
    ) -> SignedRadixCiphertext {
        assert!(self.message_modulus().0.is_power_of_two());
        let range_log_size = self.message_modulus().0.ilog2() as u64 * num_blocks;

        #[allow(clippy::int_plus_one)]
        {
            assert!(
                random_bits_count + 1 <= range_log_size,
                "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                random_bits_count, range_log_size-1, range_log_size-1,
            );
        }

        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let i = i as u64;

                if i * message_bits_count < random_bits_count {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2)
                    // block must have only one bit of random
                    if random_bits_count < (i + 1) * message_bits_count {
                        let top_message_bits_count = random_bits_count - i * message_bits_count;

                        assert!(top_message_bits_count <= message_bits_count);

                        self.key
                            .generate_oblivious_pseudo_random(seed, top_message_bits_count)
                    } else {
                        self.key
                            .generate_oblivious_pseudo_random(seed, message_bits_count)
                    }
                } else {
                    self.key.create_trivial(0)
                }
            })
            .collect::<Vec<_>>();

        SignedRadixCiphertext::from(blocks)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::integer::gen_keys_radix;
    use crate::shortint::oprf::test::test_uniformity;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    use crate::Seed;
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};

    // Helper: The "Oracle" implementation using BigInt
    // This is slow but mathematically guaranteed to be correct.
    fn oracle_mod_pow_2(exponent: u64, modulus: u64) -> u64 {
        assert!(modulus != 0, "div by 0");

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
    fn test_fuzzing_against_oracle() {
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
        //power of 2 not useful (dist = 0)
        for excluded_upper_bound in 1..20 {
            for num_input_random_bits in 0..20 {
                let random_input_upper_bound = 1 << num_input_random_bits;

                let mut density = vec![0_usize; excluded_upper_bound as usize];

                for i in 0..random_input_upper_bound {
                    let output = ((i * excluded_upper_bound) >> num_input_random_bits) as usize;

                    density[output] += 1;
                }

                let theoretical_pdf: Vec<f64> = density
                    .iter()
                    .map(|count| *count as f64 / random_input_upper_bound as f64)
                    .collect();

                let actual_distance: f64 = 1. / 2.
                    * theoretical_pdf
                        .iter()
                        .map(|p| {
                            let p_uniform = 1. / excluded_upper_bound as f64;

                            (*p - p_uniform).abs()
                        })
                        .sum::<f64>();

                let theoretical_distance = distance(excluded_upper_bound, num_input_random_bits);

                assert!(
                    (theoretical_distance - actual_distance).abs() <= theoretical_distance / 10000.,
                    "{theoretical_distance} != {actual_distance}"
                );
            }
        }
    }

    #[test]
    fn test_uniformity_par_generate_oblivious_pseudo_random_unsigned_custom_range2() {
        let num_blocks = 8;

        let sample_count: usize = 1_000;

        let p_value_limit: f64 = 0.000_1;

        let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);

        let excluded_upper_bound = 3;

        test_uniformity(sample_count, p_value_limit, excluded_upper_bound, |_seed| {
            let img = sks.par_generate_oblivious_pseudo_random_unsigned_custom_range2(
                Seed(seed as u128),
                excluded_upper_bound,
                num_blocks as u64,
                Some(2_f64.powi(-32)),
            );

            cks.decrypt(&img)
        });
    }
}
