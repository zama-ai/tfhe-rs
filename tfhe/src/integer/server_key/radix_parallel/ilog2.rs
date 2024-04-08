use crate::integer::{
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext, ServerKey,
    SignedRadixCiphertext,
};
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
        let counter_num_blocks =
            (num_bits_in_ciphertext.ilog2() + 1).div_ceil(self.message_modulus().0.ilog2());

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

    /// See [Self::trailing_zeros_parallelized]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::Zero)
    }

    /// See [Self::trailing_ones_parallelized]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_trailing_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Trailing, BitValue::One)
    }

    /// See [Self::leading_zeros_parallelized]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::Zero)
    }

    /// See [Self::leading_ones_parallelized]
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_leading_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        self.count_consecutive_bits(ct, Direction::Leading, BitValue::One)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// See [Self::ilog2_parallelized] for an example
    ///
    /// Expects ct to have clean carries
    pub fn unchecked_ilog2_parallelized<T>(&self, ct: &T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if ct.blocks().is_empty() {
            return self.create_trivial_zero_radix(ct.blocks().len());
        }

        let num_bits_in_message = self.key.message_modulus.0.ilog2();
        let original_num_blocks = ct.blocks().len();

        let num_bits_in_ciphertext = num_bits_in_message
            .checked_mul(original_num_blocks as u32)
            .expect("Number of bits encrypted exceeds u32::MAX");

        // `num_bits_in_ciphertext-1` is the max value we want to represent
        // its ilog2 + 1 gives use how many bits we need to be able to represent it.
        // We add `1` to this number as we are going to use signed numbers later
        //
        // The ilog2 of a number that is on n bits, is in range 1..=n-1
        let counter_num_blocks = ((num_bits_in_ciphertext - 1).ilog2() + 1 + 1)
            .div_ceil(self.message_modulus().0.ilog2()) as usize;

        // 11111000
        // x.ilog2() = (x.num_bit() - 1) - x.leading_zeros()
        // - (x.num_bit() - 1) is trivially known
        // - we can get leading zeros via a sum
        //
        // However, the sum include a full propagation, thus the subtraction
        // will add another full propagation which is costly.
        //
        // However, we can do better:
        // let N = (x.num_bit() - 1)
        // let L0 = x.leading_zeros()
        // ```
        // x.ilog2() = N - L0
        // x.ilog2() = -(-(N - L0))
        // x.ilog2() = -(-N + L0)
        // ```
        // Since N is a clear number, getting -N is free,
        // meaning -N + L0 where L0 is actually `sum(L0[b0], .., L0[num_blocks-1])`
        // can be done with `sum(-N, L0[b0], .., L0[num_blocks-1]), by switching to signed
        // numbers.
        //
        // Also, to do -(-N + L0) aka -sum(-N, L0[b0], .., L0[num_blocks-1])
        // we can make the sum not return a fully propagated result,
        // and extract message/carry blocks while negating them at the same time
        // using the fact that in twos complement -X = bitnot(X) + 1
        // so given a non propagated `C`, we can compute the fully propagated `PC`
        // PC = bitnot(message(C)) + bitnot(blockshift(carry(C), 1)) + 2

        let leading_zeros_per_blocks =
            self.prepare_count_of_consecutive_bits(ct.clone(), Direction::Leading, BitValue::Zero);

        let mut cts = leading_zeros_per_blocks
            .into_iter()
            .map(|block| {
                let mut ct: SignedRadixCiphertext =
                    self.create_trivial_zero_radix(counter_num_blocks);
                ct.blocks[0] = block;
                ct
            })
            .collect::<Vec<_>>();
        cts.push(
            self.create_trivial_radix(-(num_bits_in_ciphertext as i32 - 1i32), counter_num_blocks),
        );

        let result = self
            .unchecked_partial_sum_ciphertexts_vec_parallelized(cts)
            .expect("internal error, empty ciphertext count");

        // This is the part where we extract message and carry blocks
        // while inverting their bits
        let (message_blocks, carry_blocks) = rayon::join(
            || {
                let lut = self.key.generate_lookup_table(|x| {
                    // extract message
                    let x = x % self.key.message_modulus.0 as u64;
                    // bitnot the message
                    (!x) % self.key.message_modulus.0 as u64
                });
                result
                    .blocks()
                    .par_iter()
                    .map(|block| self.key.apply_lookup_table(block, &lut))
                    .collect::<Vec<_>>()
            },
            || {
                let lut = self.key.generate_lookup_table(|x| {
                    // extract carry
                    let x = x / self.key.message_modulus.0 as u64;
                    // bitnot the carry
                    (!x) % self.key.message_modulus.0 as u64
                });
                let mut carry_blocks = Vec::with_capacity(counter_num_blocks);
                result.blocks()[..counter_num_blocks - 1] // last carry is not interesting
                    .par_iter()
                    .map(|block| self.key.apply_lookup_table(block, &lut))
                    .collect_into_vec(&mut carry_blocks);
                // Normally this would be 0, but we want the bitnot of 0, which is msg_mod-1
                carry_blocks.insert(
                    0,
                    self.key
                        .create_trivial((self.message_modulus().0 - 1) as u64),
                );
                carry_blocks
            },
        );

        let message = SignedRadixCiphertext::from(message_blocks);
        let carry = SignedRadixCiphertext::from(carry_blocks);
        let result = self
            .sum_ciphertexts_parallelized(
                [
                    message,
                    carry,
                    self.create_trivial_radix(2u32, counter_num_blocks),
                ]
                .iter(),
            )
            .unwrap();

        self.cast_to_unsigned(result, counter_num_blocks)
    }

    //==============================================================================================
    //  Smart
    //==============================================================================================

    /// See [Self::trailing_zeros_parallelized]
    pub fn smart_trailing_zeros_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_trailing_zeros_parallelized(ct)
    }

    /// See [Self::trailing_ones_parallelized]
    pub fn smart_trailing_ones_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_trailing_ones_parallelized(ct)
    }

    /// See [Self::leading_zeros_parallelized]
    pub fn smart_leading_zeros_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_leading_zeros_parallelized(ct)
    }

    /// See [Self::leading_ones_parallelized]
    pub fn smart_leading_ones_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_leading_ones_parallelized(ct)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// See [Self::ilog2_parallelized] for an example
    pub fn smart_ilog2_parallelized<T>(&self, ct: &mut T) -> RadixCiphertext
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_ilog2_parallelized(ct)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// See [Self::checked_ilog2_parallelized] for an example
    ///
    /// Also returns a BooleanBlock, encrypting true (1) if the result is
    /// valid (input is > 0), otherwise 0.
    pub fn smart_checked_ilog2_parallelized<T>(&self, ct: &mut T) -> (RadixCiphertext, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        rayon::join(
            || self.ilog2_parallelized(ct),
            || self.scalar_gt_parallelized(ct, 0),
        )
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
    /// ```rust
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
    /// let n = sks.trailing_zeros_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.trailing_zeros());
    /// ```
    pub fn trailing_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
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
        self.unchecked_trailing_zeros_parallelized(ct)
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
    /// ```rust
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
    /// let n = sks.trailing_ones_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.trailing_ones());
    /// ```
    pub fn trailing_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
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
        self.unchecked_trailing_ones_parallelized(ct)
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
    /// ```rust
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
    /// let n = sks.leading_zeros_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.leading_zeros());
    /// ```
    pub fn leading_zeros_parallelized<T>(&self, ct: &T) -> RadixCiphertext
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
        self.unchecked_leading_zeros_parallelized(ct)
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
    /// ```rust
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
    /// let n = sks.leading_ones_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.leading_ones());
    /// ```
    pub fn leading_ones_parallelized<T>(&self, ct: &T) -> RadixCiphertext
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
        self.unchecked_leading_ones_parallelized(ct)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 5i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let n = sks.ilog2_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.ilog2());
    /// ```
    pub fn ilog2_parallelized<T>(&self, ct: &T) -> RadixCiphertext
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

        self.unchecked_ilog2_parallelized(ct)
    }

    /// Returns the base 2 logarithm of the number, rounded down.
    ///
    /// Also returns a BooleanBlock, encrypting true (1) if the result is
    /// valid (input is > 0), otherwise 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 5i8;
    ///
    /// let ct1 = cks.encrypt_signed(msg);
    ///
    /// let (n, is_oks) = sks.checked_ilog2_parallelized(&ct1);
    ///
    /// // Decrypt:
    /// let n: u32 = cks.decrypt(&n);
    /// assert_eq!(n, msg.ilog2());
    /// let is_ok = cks.decrypt_bool(&is_oks);
    /// assert!(is_ok);
    /// ```
    pub fn checked_ilog2_parallelized<T>(&self, ct: &T) -> (RadixCiphertext, BooleanBlock)
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

        rayon::join(
            || self.ilog2_parallelized(ct),
            || self.scalar_gt_parallelized(ct, 0),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests_unsigned {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
        FunctionExecutor, NB_CTXT, NB_TESTS_SMALLER,
    };
    use crate::integer::server_key::radix_parallel::tests_unsigned::random_non_zero_value;
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

    pub(crate) fn default_ilog2_test<P, T>(param: P, mut executor: T)
    where
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

        // Test with invalid input
        {
            let ctxt = cks.encrypt(0u64);

            let ct_res = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                .div_ceil(cks.parameters().message_modulus().0.ilog2())
                as usize;
            let expected_result = (1u32
                << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                - 1;
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for 0.ilog2() \
             expected {expected_result}, got {decrypted_result}"
            );
        }

        let input_values = (0..num_bits)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt(clear);

            let ct_res = executor.execute(&ctxt);
            let tmp = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
             expected {expected_result}, got {decrypted_result}"
            );

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                // But here, we have to make sure clear is still > 0
                // as we are only testing valid ilog2 inputs
                let (clear, clear_2) = loop {
                    let clear_2 = random_non_zero_value(&mut rng, modulus);
                    let clear = clear_2.wrapping_add(clear) % modulus;
                    if clear != 0 {
                        break (clear, clear_2);
                    }
                };

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let d0: u64 = cks.decrypt(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let ct_res = executor.execute(&ctxt);
                assert!(ct_res.block_carries_are_empty());

                let expected_result = clear.ilog2();

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2, for {clear}.ilog2() \
                 expected {expected_result}, got {decrypted_result}"
                );
            }
        }

        let input_values = (0..num_bits)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

            let ct_res = executor.execute(&ctxt);
            let tmp = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();

            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
             expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    pub(crate) fn default_checked_ilog2_test<P, T>(param: P, mut executor: T)
    where
        P: Into<PBSParameters>,
        T: for<'a> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>,
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

        // Test with invalid input
        {
            let ctxt = cks.encrypt(0u64);

            let (ct_res, is_ok) = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(is_ok.as_ref().degree.get(), 1);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                .div_ceil(cks.parameters().message_modulus().0.ilog2())
                as usize;
            let expected_result = (1u32
                << (counter_num_blocks as u32 * cks.parameters().message_modulus().0.ilog2()))
                - 1;
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for 0.ilog2() \
             expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(!is_ok);
        }

        let input_values = (0..num_bits)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt(clear);

            let (ct_res, is_ok) = executor.execute(&ctxt);
            let (tmp, tmp_is_ok) = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            assert_eq!(is_ok, tmp_is_ok);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                // But here, we have to make sure clear is still > 0
                // as we are only testing valid ilog2 inputs
                let (clear, clear_2) = loop {
                    let clear_2 = random_non_zero_value(&mut rng, modulus);
                    let clear = clear_2.wrapping_add(clear) % modulus;
                    if clear != 0 {
                        break (clear, clear_2);
                    }
                };

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let d0: u64 = cks.decrypt(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let (ct_res, is_ok) = executor.execute(&ctxt);
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(is_ok.as_ref().degree.get(), 1);

                let expected_result = clear.ilog2();

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
                );
                let is_ok = cks.decrypt_bool(&is_ok);
                assert!(is_ok);
            }
        }

        let input_values = (0..num_bits)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = sks.create_trivial_radix(clear, NB_CTXT);

            let (ct_res, is_ok) = executor.execute(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();

            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_signed {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::server_key::radix_parallel::tests_signed::{
        random_non_zero_value, signed_add_under_modulus,
    };
    use crate::integer::server_key::radix_parallel::tests_unsigned::{NB_CTXT, NB_TESTS_SMALLER};
    use crate::integer::{IntegerKeyKind, RadixClientKey};
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
            ServerKey::trailing_zeros_parallelized,
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
            ServerKey::trailing_ones_parallelized,
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
            ServerKey::leading_zeros_parallelized,
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
            ServerKey::leading_ones_parallelized,
        );
    }

    pub(crate) fn default_ilog2_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cks = RadixClientKey::from((cks, NB_CTXT));

        sks.set_deterministic_pbs_execution(true);

        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

        let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

        // Test with invalid input
        {
            for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
                let ctxt = cks.encrypt_signed(clear);

                let ct_res = sks.ilog2_parallelized(&ctxt);
                assert!(ct_res.block_carries_are_empty());

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                let expected_result = if clear < 0 {
                    num_bits - 1
                } else {
                    let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                        .div_ceil(cks.parameters().message_modulus().0.ilog2())
                        as usize;
                    (1u32
                        << (counter_num_blocks as u32
                            * cks.parameters().message_modulus().0.ilog2()))
                        - 1
                };
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
                );
            }
        }

        let input_values = (0..num_bits - 1)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt_signed(clear);

            let ct_res = sks.ilog2_parallelized(&ctxt);
            let tmp = sks.ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                // But here, we have to make sure clear is still > 0
                // as we are only testing valid ilog2 inputs
                let (clear, clear_2) = loop {
                    let clear_2 = random_non_zero_value(&mut rng, modulus);
                    let clear = signed_add_under_modulus(clear, clear_2, modulus);
                    if clear > 0 {
                        break (clear, clear_2);
                    }
                };

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let d0: i64 = cks.decrypt_signed(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let ct_res = sks.ilog2_parallelized(&ctxt);
                assert!(ct_res.block_carries_are_empty());

                let expected_result = clear.ilog2();

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
                );
            }
        }

        let input_values = (0..num_bits - 1)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

            let ct_res = sks.ilog2_parallelized(&ctxt);
            let tmp = sks.ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();

            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );
        }
    }

    pub(crate) fn default_checked_ilog2_test<P>(param: P)
    where
        P: Into<PBSParameters>,
    {
        let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
        let cks = RadixClientKey::from((cks, NB_CTXT));

        sks.set_deterministic_pbs_execution(true);

        let mut rng = rand::thread_rng();

        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

        let num_bits = NB_CTXT as u32 * cks.parameters().message_modulus().0.ilog2();

        // Test with invalid input
        {
            for clear in [0i64, rng.gen_range(-modulus..=-1i64)] {
                let ctxt = cks.encrypt_signed(clear);

                let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
                assert!(ct_res.block_carries_are_empty());

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                let expected_result = if clear < 0 {
                    num_bits - 1
                } else {
                    let counter_num_blocks = ((num_bits - 1).ilog2() + 1 + 1)
                        .div_ceil(cks.parameters().message_modulus().0.ilog2())
                        as usize;
                    (1u32
                        << (counter_num_blocks as u32
                            * cks.parameters().message_modulus().0.ilog2()))
                        - 1
                };
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2 for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
                );
                let is_ok = cks.decrypt_bool(&is_ok);
                assert!(!is_ok);
            }
        }

        let input_values = (0..num_bits - 1)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt = cks.encrypt_signed(clear);

            let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
            let (tmp, tmp_is_ok) = sks.checked_ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            assert_eq!(is_ok, tmp_is_ok);

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2 for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);

            for _ in 0..NB_TESTS_SMALLER {
                // Add non-zero scalar to have non-clean ciphertexts
                // But here, we have to make sure clear is still > 0
                // as we are only testing valid ilog2 inputs
                let (clear, clear_2) = loop {
                    let clear_2 = random_non_zero_value(&mut rng, modulus);
                    let clear = signed_add_under_modulus(clear, clear_2, modulus);
                    if clear > 0 {
                        break (clear, clear_2);
                    }
                };

                let ctxt = sks.unchecked_scalar_add(&ctxt, clear_2);

                let d0: i64 = cks.decrypt_signed(&ctxt);
                assert_eq!(d0, clear, "Failed sanity decryption check");

                let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(is_ok.as_ref().degree.get(), 1);

                let expected_result = clear.ilog2();

                let decrypted_result: u32 = cks.decrypt(&ct_res);
                assert_eq!(
                    decrypted_result, expected_result,
                    "Invalid result for ilog2, for {clear}.ilog2() \
                    expected {expected_result}, got {decrypted_result}"
                );
                let is_ok = cks.decrypt_bool(&is_ok);
                assert!(is_ok);
            }
        }

        let input_values = (0..num_bits - 1)
            .map(|i| 1 << i)
            .chain(
                (0..NB_TESTS_SMALLER.saturating_sub(num_bits as usize))
                    .map(|_| rng.gen_range(1..modulus)),
            )
            .collect::<Vec<_>>();

        for clear in input_values {
            let ctxt: SignedRadixCiphertext = sks.create_trivial_radix(clear, NB_CTXT);

            let (ct_res, is_ok) = sks.checked_ilog2_parallelized(&ctxt);
            assert!(ct_res.block_carries_are_empty());

            let decrypted_result: u32 = cks.decrypt(&ct_res);
            let expected_result = clear.ilog2();

            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for ilog2, for {clear}.ilog2() \
                expected {expected_result}, got {decrypted_result}"
            );
            let is_ok = cks.decrypt_bool(&is_ok);
            assert!(is_ok);
        }
    }
}
