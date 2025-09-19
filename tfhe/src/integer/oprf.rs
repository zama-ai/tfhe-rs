use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::DefaultRandomGenerator;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::cmp::Ordering;

pub use tfhe_csprng::seeders::{Seed, Seeder};

impl ServerKey {
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in its full range using the given seed.
    /// The encryted value is oblivious to the server.
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

        assert!(self.message_modulus().0.is_power_of_two());
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
    /// The encryted value is oblivious to the server.
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

        assert!(self.message_modulus().0.is_power_of_two());
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
    /// The encryted value is oblivious to the server.
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

        assert!(!excluded_upper_bound.is_power_of_two());

        assert!(
            (excluded_upper_bound as f64).log2()
                < (num_blocks_output * self.message_modulus().0) as f64
        );

        assert!(self.message_modulus().0.is_power_of_two());
        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let post_mul_log2_range =
            num_input_random_bits as f64 + (excluded_upper_bound as f64).log2();

        let num_blocks = (post_mul_log2_range / message_bits_count as f64).ceil() as usize;

        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let in_blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let i = i as u64;

                if i * message_bits_count < num_input_random_bits {
                    // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2) block
                    // must have only one bit of random
                    if num_input_random_bits < (i + 1) * message_bits_count {
                        let top_message_bits_count = num_input_random_bits - i * message_bits_count;

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

        let input = RadixCiphertext::from(in_blocks);

        let before_shift: crate::integer::ciphertext::BaseRadixCiphertext<
            crate::shortint::Ciphertext,
        > = self.scalar_mul_parallelized(&input, excluded_upper_bound);

        let mut result = self.scalar_right_shift_parallelized(&before_shift, num_input_random_bits);

        // Adjust the number of leading (MSB) trivial zeros blocks
        loop {
            match result.blocks.len().cmp(&(num_blocks_output as usize)) {
                Ordering::Less => result.blocks.push(self.key.create_trivial(0)),
                Ordering::Equal => {
                    break;
                }
                Ordering::Greater => {
                    let leading_block = result.blocks.pop().unwrap();

                    assert!(leading_block.is_trivial());
                }
            }
        }

        result
    }
}

impl ServerKey {
    /// Generates an encrypted `num_block` blocks signed integer
    /// taken uniformly in its full range using the given seed.
    /// The encryted value is oblivious to the server.
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
    /// The encryted value is oblivious to the server.
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

        assert!(self.message_modulus().0.is_power_of_two());
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
pub(crate) mod test {
    use crate::core_crypto::commons::math::random::tests::{
        cumulate, dkw_alpha_from_value, sup_diff,
    };
    use crate::integer::gen_keys_radix;
    use crate::shortint::oprf::test::test_uniformity;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    use tfhe_csprng::seeders::Seed;

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 10_000;

        let p_value_limit: f64 = 0.000_01;

        let random_bits_count = 3;

        let num_blocks = 2;

        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);

        let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
            test_uniformity(sample_count, p_value_limit, distinct_values, f)
        };

        test_uniformity(1 << random_bits_count, &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                Seed(seed as u128),
                random_bits_count,
                num_blocks as u64,
            );
            ck.decrypt(&img)
        });

        test_uniformity(1 << random_bits_count, &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_signed_integer_bounded(
                Seed(seed as u128),
                random_bits_count,
                num_blocks as u64,
            );
            let result = ck.decrypt_signed::<i64>(&img);

            assert!(result >= 0);

            result as u64
        });

        test_uniformity(1 << (2 * num_blocks), &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_signed_integer(
                Seed(seed as u128),
                num_blocks as u64,
            );

            // Move from [-2^(p-1), 2^(p-1)[ to [0, 2^p[ (p = 2 * num_blocks)
            let result = ck.decrypt_signed::<i64>(&img) + (1 << (2 * num_blocks - 1));

            assert!(result >= 0);

            result as u64
        });
    }

    #[test]
    fn oprf_test_any_range_ci_run_filter() {
        let num_blocks_output = 64;

        let (ck, sk) = gen_keys_radix(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            num_blocks_output,
        );

        let num_loops = 100;

        for seed in 0..num_loops {
            let seed = Seed(seed);

            for num_input_random_bits in [64] {
                for (excluded_upper_bound, num_blocks_output) in
                    [(3, 1), (3, 32), ((1 << 32) + 1, 64)]
                {
                    let img = sk.par_generate_oblivious_pseudo_random_unsigned_custom_range(
                        seed,
                        num_input_random_bits,
                        excluded_upper_bound,
                        num_blocks_output as u64,
                    );

                    assert_eq!(img.blocks.len(), num_blocks_output);

                    let decrypted: u64 = ck.decrypt(&img);

                    assert!(decrypted < excluded_upper_bound);
                }
            }
        }
    }

    #[test]
    fn oprf_test_almost_uniformity_ci_run_filter() {
        let sample_count: usize = 10_000;

        let p_value_limit: f64 = 0.001;

        let num_input_random_bits: usize = 4;

        let num_blocks_output = 64;

        let excluded_upper_bound = 10;

        let (ck, sk) = gen_keys_radix(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            num_blocks_output,
        );

        let mut density = vec![0_usize; excluded_upper_bound];

        for i in 0..1 << num_input_random_bits {
            let index = ((i * excluded_upper_bound) as f64
                / 2_f64.powi(num_input_random_bits as i32)) as usize;

            density[index] += 1;
        }

        //probability density function
        let theoretical_pdf: Vec<f64> = density
            .iter()
            .map(|count| *count as f64 / (1 << num_input_random_bits) as f64)
            .collect();

        let values: Vec<u64> = (0..sample_count)
            .into_par_iter()
            .map(|seed| {
                let img = sk.par_generate_oblivious_pseudo_random_unsigned_custom_range(
                    Seed(seed as u128),
                    num_input_random_bits as u64,
                    excluded_upper_bound as u64,
                    num_blocks_output as u64,
                );
                ck.decrypt(&img)
            })
            .collect();

        let mut bins = vec![0_u64; excluded_upper_bound];

        for value in values {
            bins[value as usize] += 1;
        }

        let cumulative_bins = cumulate(&bins);

        let theoretical_cdf = cumulate(&theoretical_pdf);

        let sup_diff = sup_diff(&cumulative_bins, &theoretical_cdf);

        let p_value_upper_bound = dkw_alpha_from_value(sample_count as f64, sup_diff);

        println!("p_value_upper_bound {p_value_upper_bound}");

        assert!(p_value_limit < p_value_upper_bound);
    }
}
