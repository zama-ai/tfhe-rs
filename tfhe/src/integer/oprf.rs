use super::{RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::DefaultRandomGenerator;
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
