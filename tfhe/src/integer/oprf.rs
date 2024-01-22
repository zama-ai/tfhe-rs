use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::ActivatedRandomGenerator;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

pub use concrete_csprng::seeders::{Seed, Seeder};

impl ServerKey {
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed
    /// The encryted value is oblivious to the server
    /// It can be useful to make server random generation deterministic
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_unsigned_integer(
    ///     Seed(0),
    ///     random_bits_count,
    ///     size as u64,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_unsigned_integer(
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

        let mut deterministic_seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);

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
}

// Describes in which range a random signed integer should be generated
#[derive(Copy, Clone)]
pub enum SignedRandomizationSpec {
    // taken uniformly in `[0, 2^random_bits_count[`
    Unsigned { random_bits_count: u64 },
    // taken uniformly in the full range [-2^(p-1), 2^(p-1)[
    FullSigned,
}

impl ServerKey {
    /// Generates an encrypted `num_block` blocks signed integer
    /// using the given seed following the randomizer spec
    /// The encryted value is oblivious to the server
    /// It can be useful to make server random generation deterministic
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::oprf::SignedRandomizationSpec;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::Seed;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let ct_res = sks.par_generate_oblivious_pseudo_random_signed_integer(
    ///     Seed(0),
    ///     SignedRandomizationSpec::FullSigned,
    ///     size as u64,
    /// );
    ///
    /// // Decrypt:
    /// let dec_result: i64 = cks.decrypt_signed(&ct_res);
    /// assert!(dec_result < 1 << (2 * size - 1));
    /// assert!(dec_result >= -(1 << (2 * size - 1)));
    /// ```
    pub fn par_generate_oblivious_pseudo_random_signed_integer(
        &self,
        seed: Seed,
        randomizer: SignedRandomizationSpec,
        num_blocks: u64,
    ) -> SignedRadixCiphertext {
        #[allow(clippy::int_plus_one)]
        if let SignedRandomizationSpec::Unsigned { random_bits_count } = randomizer {
            assert!(self.message_modulus().0.is_power_of_two());
            let range_log_size = self.message_modulus().0.ilog2() as u64 * num_blocks;

            assert!(
                random_bits_count + 1 <= range_log_size,
                "The range asked for a random value (=[0, 2^{}[) does not fit in the available range [-2^{}, 2^{}[",
                random_bits_count, range_log_size-1, range_log_size-1,
            );
        }

        assert!(self.message_modulus().0.is_power_of_two());
        let message_bits_count = self.message_modulus().0.ilog2() as u64;

        let mut deterministic_seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);

        let seeds: Vec<Seed> = (0..num_blocks)
            .map(|_| deterministic_seeder.seed())
            .collect();

        let blocks = seeds
            .into_par_iter()
            .enumerate()
            .map(|(i, seed)| {
                let i = i as u64;

                match randomizer {
                    SignedRandomizationSpec::Unsigned { random_bits_count } => {
                        if i * message_bits_count < random_bits_count {
                            // if we generate 5 bits of noise in n blocks of 2 bits, the third (i=2)
                            // block must have only one bit of random
                            if random_bits_count < (i + 1) * message_bits_count {
                                let top_message_bits_count =
                                    random_bits_count - i * message_bits_count;

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
                    }
                    SignedRandomizationSpec::FullSigned => self
                        .key
                        .generate_oblivious_pseudo_random(seed, message_bits_count),
                }
            })
            .collect::<Vec<_>>();

        SignedRadixCiphertext::from(blocks)
    }
}

#[cfg(test)]
pub(crate) mod test {

    use crate::integer::oprf::SignedRandomizationSpec;
    use crate::shortint::oprf::test::test_uniformity;
    use concrete_csprng::seeders::Seed;

    #[test]
    fn oprf_test_uniformity_ci_run_filter() {
        let sample_count: usize = 10_000;

        let p_value_limit: f64 = 0.001;

        let random_bits_count = 3;

        let num_blocks = 2;

        use crate::integer::gen_keys_radix;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);

        let test_uniformity = |distinct_values: u64, f: &(dyn Fn(usize) -> u64 + Sync)| {
            test_uniformity(sample_count, p_value_limit, distinct_values, f)
        };

        test_uniformity(1 << random_bits_count, &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                Seed(seed as u128),
                random_bits_count,
                num_blocks as u64,
            );
            ck.decrypt(&img)
        });

        test_uniformity(1 << random_bits_count, &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_signed_integer(
                Seed(seed as u128),
                SignedRandomizationSpec::Unsigned { random_bits_count },
                num_blocks as u64,
            );
            let result = ck.decrypt_signed::<i64>(&img);

            assert!(result >= 0);

            result as u64
        });

        test_uniformity(1 << (2 * num_blocks), &|seed| {
            let img = sk.par_generate_oblivious_pseudo_random_signed_integer(
                Seed(seed as u128),
                SignedRandomizationSpec::FullSigned,
                num_blocks as u64,
            );

            // Move from [-2^(p-1), 2^(p-1)[ to [0, 2^p[ (p = 2 * num_blocks)
            let result = ck.decrypt_signed::<i64>(&img) + (1 << (2 * num_blocks - 1));

            assert!(result >= 0);

            result as u64
        });
    }
}
