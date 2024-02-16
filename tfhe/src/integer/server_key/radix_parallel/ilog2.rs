use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext, ServerKey};

use crate::shortint::Ciphertext;

use rayon::prelude::*;

/// A 'bit' value
///
/// Used to improved readability over using a `bool`.
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u64)]
enum BitValue {
    Zero = 0,
    One = 1,
}

impl BitValue {
    fn opposite(self) -> Self {
        match self {
            Self::One => Self::Zero,
            Self::Zero => Self::One,
        }
    }
}

/// Direction to count consecutive bits
#[derive(Copy, Clone, Eq, PartialEq)]
enum Direction {
    /// Count starting from the LSB
    Trailing,
    /// Count starting from MSB
    Leading,
}

impl ServerKey {
    /// This function takes a ciphertext in radix representation
    /// and returns a vec of blocks, where each blocks holds the number of leading_zeros/ones
    ///
    /// This contains the logic of making a block have 0 leading_ones/zeros if its preceding
    /// block was not full of ones/zeros
    fn prepare_count_of_consecutive_bits<T>(
        &self,
        ct: T,
        direction: Direction,
        bit_value: BitValue,
    ) -> Vec<Ciphertext>
    where
        T: IntegerRadixCiphertext,
    {
        assert!(
            self.carry_modulus().0 >= self.message_modulus().0,
            "A carry modulus as least as big as the message modulus is required"
        );

        let mut blocks = ct.into_blocks();

        let lut = match direction {
            Direction::Trailing => self.key.generate_lookup_table(|x| {
                let x = x % self.key.message_modulus.0 as u64;

                let mut count = 0;
                for i in 0..self.key.message_modulus.0.ilog2() {
                    if (x >> i) & 1 == bit_value.opposite() as u64 {
                        break;
                    }
                    count += 1;
                }
                count
            }),
            Direction::Leading => self.key.generate_lookup_table(|x| {
                let x = x % self.key.message_modulus.0 as u64;

                let mut count = 0;
                for i in (0..self.key.message_modulus.0.ilog2()).rev() {
                    if (x >> i) & 1 == bit_value.opposite() as u64 {
                        break;
                    }
                    count += 1;
                }
                count
            }),
        };

        // Assign to each block its number of leading/trailing zeros/ones
        // in the message space
        blocks.par_iter_mut().for_each(|block| {
            self.key.apply_lookup_table_assign(block, &lut);
        });

        if direction == Direction::Leading {
            // Our blocks are from lsb to msb
            // `leading` means starting from the msb, so we reverse block
            // for the cum sum process done later
            blocks.reverse();
        }

        // Use hillis-steele cumulative-sum algorithm
        // Here, each block either keeps his value (the number of leading zeros)
        // or becomes 0 if the preceding block
        // had a bit set to one in it (leading_zeros != num bits in message)
        let num_bits_in_message = self.key.message_modulus.0.ilog2() as u64;
        let sum_lut = self.key.generate_lookup_table_bivariate(
            |block_num_bit_count, more_significant_block_bit_count| {
                if more_significant_block_bit_count == num_bits_in_message {
                    block_num_bit_count
                } else {
                    0
                }
            },
        );

        let sum_function =
            |block_num_bit_count: &mut Ciphertext,
             more_significant_block_bit_count: &Ciphertext| {
                self.key.unchecked_apply_lookup_table_bivariate_assign(
                    block_num_bit_count,
                    more_significant_block_bit_count,
                    &sum_lut,
                );
            };
        self.compute_prefix_sum_hillis_steele(blocks, sum_function)
    }

    /// Counts how many consecutive bits there are
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    fn count_consecutive_bits<T>(
        &self,
        ct: &T,
        direction: Direction,
        bit_value: BitValue,
    ) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if ct.blocks().is_empty() {
            return self.create_trivial_zero_radix(0);
        }

        let num_bits_in_message = self.key.message_modulus.0.ilog2();
        let original_num_blocks = ct.blocks().len();

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(original_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        let leading_count_per_blocks =
            self.prepare_count_of_consecutive_bits(ct.clone(), direction, bit_value);

        // `num_bits_in_ciphertext` is the max value we want to represent
        // its ilog2 + 1 gives use how many bits we need to be able to represent it.
        let counter_num_blocks = divide_ceil(
            num_bits_in_ciphertext.ilog2() + 1,
            self.message_modulus().0.ilog2(),
        );

        let cts = leading_count_per_blocks
            .into_iter()
            .map(|block| {
                let mut ct: RadixCiphertext =
                    self.create_trivial_zero_radix(counter_num_blocks as usize);
                ct.blocks[0] = block;
                ct
            })
            .collect::<Vec<_>>();

        self.unchecked_sum_ciphertexts_vec_parallelized(cts)
            .expect("internal error, empty ciphertext count")
    }

    //==============================================================================================
    //  Unchecked
    //==============================================================================================

    /// See [Self::trailing_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_zeros<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::Zero)
    }

    /// See [Self::trailing_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_ones<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::One)
    }

    /// See [Self::leading_zeros]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_zeros<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::Zero)
    }

    /// See [Self::leading_ones]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_ones<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::One)
    }

    //==============================================================================================
    //  Smart
    //==============================================================================================

    /// See [Self::trailing_zeros]
    pub fn smart_trailing_zeros<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_trailing_zeros(ct)
    }

    /// See [Self::trailing_ones]
    pub fn smart_trailing_ones<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_trailing_ones(ct)
    }

    /// See [Self::leading_zeros]
    pub fn smart_leading_zeros<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_leading_zeros(ct)
    }

    /// See [Self::leading_ones]
    pub fn smart_leading_ones<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_leading_ones(ct)
    }

    //==============================================================================================
    //  Default
    //==============================================================================================

    /// Returns the number of trailing zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = -4i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let n = sks.trailing_zeros(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.trailing_zeros());
    /// ```
    pub fn trailing_zeros<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.clone();
            self.full_propagate_parallelized(&mut tmp);
            &tmp
        };
        self.unchecked_trailing_zeros(ct)
    }

    /// Returns the number of trailing ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = -4i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let n = sks.trailing_ones(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.trailing_ones());
    /// ```
    pub fn trailing_ones<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.clone();
            self.full_propagate_parallelized(&mut tmp);
            &tmp
        };
        self.unchecked_trailing_ones(ct)
    }

    /// Returns the number of leading zeros in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = -4i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let n = sks.leading_zeros(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.leading_zeros());
    /// ```
    pub fn leading_zeros<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.clone();
            self.full_propagate_parallelized(&mut tmp);
            &tmp
        };
        self.unchecked_leading_zeros(ct)
    }

    /// Returns the number of leading ones in the binary representation of `ct`
    ///
    /// The returned Ciphertexts has a variable size
    /// i.e. It contains just the minimum number of block
    /// needed to represent the maximum possible number of bits.
    ///
    /// This is a default function, it will internally clone the ciphertext if it has
    /// non propagated carries, and it will output a ciphertext without any carries.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = -4i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let n = sks.leading_ones(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.leading_ones());
    /// ```
    pub fn leading_ones<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp;
        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp = ct.clone();
            self.full_propagate_parallelized(&mut tmp);
            &tmp
        };
        self.unchecked_leading_ones(ct)
    }
}

#[cfg(test)]
pub(crate) mod tests_unsigned {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
        random_non_zero_value, FunctionExecutor, NB_CTXT, NB_TESTS_SMALLER,
    };
    use crate::integer::{IntegerKeyKind, RadixClientKey};
    use crate::shortint::PBSParameters;
    use rand::Rng;
    use std::sync::Arc;

    fn default_test_count_consecutive_bits<P, T>(
        direction: Direction,
        bit_value: BitValue,
        param: P,
        mut executor: T,
    ) where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cks = RadixClientKey::from((cks, NB_CTXT));

        sks.set_deterministic_pbs_execution(true);
        let sks = Arc::new(sks);

        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

        executor.setup(&cks, sks.clone());

        let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

        let compute_expected_clear = |x: u64| match (direction, bit_value) {
            (Direction::Trailing, BitValue::Zero) => {
                if x == 0 {
                    num_bits
                } else {
                    x.trailing_zeros()
                }
            }
            (Direction::Trailing, BitValue::One) => x.trailing_ones(),
            (Direction::Leading, BitValue::Zero) => {
                if x == 0 {
                    num_bits
                } else {
                    (x << (u64::BITS - num_bits)).leading_zeros()
                }
            }
            (Direction::Leading, BitValue::One) => (x << (u64::BITS - num_bits)).leading_ones(),
        };

        let method_name = match (direction, bit_value) {
            (Direction::Trailing, BitValue::Zero) => "trailing_zeros",
            (Direction::Trailing, BitValue::One) => "trailing_ones",
            (Direction::Leading, BitValue::Zero) => "leading_zeros",
            (Direction::Leading, BitValue::One) => "leading_ones",
        };

        let input_values = [0u64, modulus - 1]
            .into_iter()
            .chain((0..NB_TESTS_SMALLER).map(|_| rng.gen::<u64>() % modulus))
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt(clear);

            let ct_res = executor.execute(&ctxt);
            let tmp = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = compute_expected_clear(clear);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
             expected {expected_result}, got {decrypted_result}"
            );

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, modulus);

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let clear = clear.wrapping_add(clear_2) % modulus;

                let d0: u64 = cks.decrypt(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let ct_res = executor.execute(&ctxt);
                assert!(ct_res.block_carries_are_empty());

                let expected_result = compute_expected_clear(clear);

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for {method_name}, for {clear}.{method_name}() \
                 expected {expected_result}, got {decrypted_result}"
                );
            }
        }

        let input_values = [0u64, modulus - 1]
            .into_iter()
            .chain((0..NB_TESTS_SMALLER).map(|_| rng.gen::<u64>() % modulus));

        for clear in input_values {
            let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

            let ct_res = executor.execute(&ctxt);
            let tmp = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = compute_expected_clear(clear);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
             expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    pub(crate) fn default_trailing_zeros_test<P, T>(param: P, executor: T)
    where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        default_test_count_consecutive_bits(Direction::Trailing, BitValue::Zero, param, executor);
    }

    pub(crate) fn default_trailing_ones_test<P, T>(param: P, executor: T)
    where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        default_test_count_consecutive_bits(Direction::Trailing, BitValue::One, param, executor);
    }

    pub(crate) fn default_leading_zeros_test<P, T>(param: P, executor: T)
    where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        default_test_count_consecutive_bits(Direction::Leading, BitValue::Zero, param, executor);
    }

    pub(crate) fn default_leading_ones_test<P, T>(param: P, executor: T)
    where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
    {
        default_test_count_consecutive_bits(Direction::Leading, BitValue::One, param, executor);
    }
}

#[cfg(test)]
pub(crate) mod tests_signed {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::server_key::radix_parallel::tests_signed::{
        random_non_zero_value, signed_add_under_modulus, NB_CTXT, NB_TESTS_SMALLER,
    };
    use crate::integer::{IntegerKeyKind, RadixClientKey, SignedRadixCiphertext};
    use crate::shortint::PBSParameters;
    use rand::Rng;

    fn default_test_count_consecutive_bits<P, F>(
        direction: Direction,
        bit_value: BitValue,
        param: P,
        sks_method: F,
    ) where
        P: Into<PBSParameters>,
        F: for<'a> Fn(&'a ServerKey, &'a SignedRadixCiphertext) -> RadixCiphertext,
    {
        let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cks = RadixClientKey::from((cks, NB_CTXT));

        sks.set_deterministic_pbs_execution(true);

        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

        let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

        let compute_expected_clear = |x: i64| match (direction, bit_value) {
            (Direction::Trailing, BitValue::Zero) => {
                if x == 0 {
                    num_bits
                } else {
                    x.trailing_zeros()
                }
            }
            (Direction::Trailing, BitValue::One) => x.trailing_ones().min(num_bits),
            (Direction::Leading, BitValue::Zero) => {
                if x == 0 {
                    num_bits
                } else {
                    (x << (u64::BITS - num_bits)).leading_zeros()
                }
            }
            (Direction::Leading, BitValue::One) => (x << (u64::BITS - num_bits)).leading_ones(),
        };

        let method_name = match (direction, bit_value) {
            (Direction::Trailing, BitValue::Zero) => "trailing_zeros",
            (Direction::Trailing, BitValue::One) => "trailing_ones",
            (Direction::Leading, BitValue::Zero) => "leading_zeros",
            (Direction::Leading, BitValue::One) => "leading_ones",
        };

        let input_values = [-modulus, 0i64, modulus - 1]
            .into_iter()
            .chain((0..NB_TESTS_SMALLER).map(|_| rng.gen::<i64>() % modulus))
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt_signed(clear);

            let ct_res = sks_method(&sks, &ctxt);
            let tmp = sks_method(&sks, &ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = compute_expected_clear(clear);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
            );

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                let clear_2 = random_non_zero_value(&mut rng, modulus);

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let clear = signed_add_under_modulus(clear, clear_2, modulus);

                let d0: i64 = cks.decrypt_signed(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let ct_res = sks_method(&sks, &ctxt);
                assert!(ct_res.block_carries_are_empty());

                let expected_result = compute_expected_clear(clear);

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for {method_name}, for {clear}.{method_name}() \
                    expected {expected_result}, got {decrypted_result}"
                );
            }
        }

        let input_values = [-modulus, 0i64, modulus - 1]
            .into_iter()
            .chain((0..NB_TESTS_SMALLER).map(|_| rng.gen::<i64>() % modulus));

        for clear in input_values {
            let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

            let ct_res = sks_method(&sks, &ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = compute_expected_clear(clear);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for {method_name}, for {clear}.{method_name}() \
                expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    pub(crate) fn default_trailing_zeros_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        default_test_count_consecutive_bits(
            Direction::Trailing,
            BitValue::Zero,
            param,
            ServerKey::trailing_zeros,
        );
    }

    pub(crate) fn default_trailing_ones_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        default_test_count_consecutive_bits(
            Direction::Trailing,
            BitValue::One,
            param,
            ServerKey::trailing_ones,
        );
    }

    pub(crate) fn default_leading_zeros_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        default_test_count_consecutive_bits(
            Direction::Leading,
            BitValue::Zero,
            param,
            ServerKey::leading_zeros,
        );
    }

    pub(crate) fn default_leading_ones_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        default_test_count_consecutive_bits(
            Direction::Leading,
            BitValue::One,
            param,
            ServerKey::leading_ones,
        );
    }
}
