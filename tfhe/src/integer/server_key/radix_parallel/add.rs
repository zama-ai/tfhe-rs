use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::Ciphertext;
use rayon::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ComputationFlags {
    None,
    Overflow,
    Carry,
}

impl ComputationFlags {
    pub(crate) const fn from_signedness(is_signed: bool) -> Self {
        if is_signed {
            Self::Overflow
        } else {
            Self::Carry
        }
    }
}

fn should_hillis_steele_propagation_be_faster(num_blocks: usize, num_threads: usize) -> bool {
    // Measures have shown that using a parallelized algorithm degrades
    // the latency of a PBS, so we take that into account.
    // (This factor is a bit pessimistic).
    const PARALLEL_LATENCY_PENALTY: usize = 2;
    // However that penalty only kicks in when certain level of
    // parallelism is used
    let penalty_threshold = num_threads / 2;

    // The unit of latency is a PBS
    let compute_latency_of_one_layer = |num_blocks: usize, num_threads: usize| -> usize {
        let latency = num_blocks.div_ceil(num_threads);
        if num_blocks >= penalty_threshold {
            latency * PARALLEL_LATENCY_PENALTY
        } else {
            latency
        }
    };

    // Estimate the latency of the parallelized algorithm
    let mut parallel_expected_latency = 2 * compute_latency_of_one_layer(num_blocks, num_threads);
    let max_depth = num_blocks.ceil_ilog2();
    let mut space = 1;
    for _ in 0..max_depth {
        let num_block_at_iter = num_blocks - space;
        let iter_latency = compute_latency_of_one_layer(num_block_at_iter, num_threads);
        parallel_expected_latency += iter_latency;
        space *= 2;
    }

    // the other algorithm has num_blocks latency
    parallel_expected_latency < num_blocks
}

impl ServerKey {
    pub fn unchecked_add_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = lhs.clone();
        self.unchecked_add_assign_parallelized(&mut result, rhs);
        result
    }

    pub fn unchecked_add_assign_parallelized<T>(&self, lhs: &mut T, rhs: &T)
    where
        T: IntegerRadixCiphertext,
    {
        lhs.blocks_mut()
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_add_assign(ct_left_i, ct_right_i);
            });
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add_parallelized(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn smart_add_parallelized<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_add_possible(ct_left, ct_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }

        self.is_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_add(ct_left, ct_right)
    }

    pub fn smart_add_assign_parallelized<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_add_possible(ct_left, ct_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }

        self.is_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_add_assign(ct_left, ct_right);
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn add_parallelized<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct_left.clone();
        self.add_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }

    pub fn add_assign_parallelized<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs: T;

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct_left);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct_left, &tmp_rhs)
            }
        };

        self.add_assign_with_carry(lhs, rhs, None);
    }

    /// Computes the addition of two ciphertexts and returns the overflow flag
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = u8::MAX;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let (ct_res, overflowed) = sks.unsigned_overflowing_add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// let dec_overflowed = cks.decrypt_bool(&overflowed);
    /// let (expected_result, expected_overflow) = msg1.overflowing_add(msg2);
    /// assert_eq!(dec_result, expected_result);
    /// assert_eq!(dec_overflowed, expected_overflow);
    /// ```
    pub fn overflowing_add_parallelized<T>(&self, ct_left: &T, ct_right: &T) -> (T, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct_left.clone();
        let overflowed = self.overflowing_add_assign_parallelized(&mut ct_res, ct_right);
        (ct_res, overflowed)
    }

    pub fn overflowing_add_assign_parallelized<T>(
        &self,
        ct_left: &mut T,
        ct_right: &T,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs: T;
        if ct_left.blocks().is_empty() || ct_right.blocks().is_empty() {
            return self.create_trivial_boolean_block(false);
        }

        let (lhs, rhs) = match (
            ct_left.block_carries_are_empty(),
            ct_right.block_carries_are_empty(),
        ) {
            (true, true) => (ct_left, ct_right),
            (true, false) => {
                tmp_rhs = ct_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct_left);
                (ct_left, ct_right)
            }
            (false, false) => {
                tmp_rhs = ct_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct_left, &tmp_rhs)
            }
        };

        self.overflowing_add_assign_with_carry(lhs, rhs, None)
    }

    /// Computes the addition of two unsigned ciphertexts and returns the overflow flag
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = u8::MAX;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let (ct_res, overflowed) = sks.unsigned_overflowing_add_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u8 = cks.decrypt(&ct_res);
    /// let dec_overflowed = cks.decrypt_bool(&overflowed);
    /// let (expected_result, expected_overflow) = msg1.overflowing_add(msg2);
    /// assert_eq!(dec_result, expected_result);
    /// assert_eq!(dec_overflowed, expected_overflow);
    /// ```
    pub fn unsigned_overflowing_add_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        self.overflowing_add_parallelized(ct_left, ct_right)
    }

    pub fn unsigned_overflowing_add_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> BooleanBlock {
        self.overflowing_add_assign_parallelized(ct_left, ct_right)
    }

    pub fn signed_overflowing_add_parallelized(
        &self,
        ct_left: &SignedRadixCiphertext,
        ct_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        self.overflowing_add_parallelized(ct_left, ct_right)
    }

    pub fn unchecked_signed_overflowing_add_parallelized(
        &self,
        ct_left: &SignedRadixCiphertext,
        ct_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        assert_eq!(
            ct_left.blocks.len(),
            ct_right.blocks.len(),
            "lhs and rhs must have the name number of blocks ({} vs {})",
            ct_left.blocks.len(),
            ct_right.blocks.len()
        );
        assert!(!ct_left.blocks.is_empty(), "inputs cannot be empty");

        let mut result = ct_left.clone();
        let overflowed = self.overflowing_add_assign_with_carry(&mut result, ct_right, None);
        (result, overflowed)
    }

    pub(crate) fn is_eligible_for_parallel_single_carry_propagation<T>(&self, ct: &T) -> bool
    where
        T: IntegerRadixCiphertext,
    {
        // having 4-bits is a hard requirement
        // as the parallel implementation uses a bivariate BPS where individual values need
        // 2 bits
        let total_modulus = self.key.message_modulus.0 * self.key.carry_modulus.0;
        let has_enough_bits_per_block = total_modulus >= (1 << 4);
        if !has_enough_bits_per_block {
            return false;
        }

        should_hillis_steele_propagation_be_faster(ct.blocks().len(), rayon::current_num_threads())
    }

    /// Does lhs += (rhs + carry)
    pub fn add_assign_with_carry<T>(&self, lhs: &mut T, rhs: &T, input_carry: Option<&BooleanBlock>)
    where
        T: IntegerRadixCiphertext,
    {
        self.advanced_add_assign_with_carry(
            lhs.blocks_mut(),
            rhs.blocks(),
            input_carry,
            ComputationFlags::None,
        );
    }

    /// Does lhs += (rhs + carry)
    pub fn overflowing_add_assign_with_carry<T>(
        &self,
        lhs: &mut T,
        rhs: &T,
        input_carry: Option<&BooleanBlock>,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.advanced_add_assign_with_carry(
            lhs.blocks_mut(),
            rhs.blocks(),
            input_carry,
            ComputationFlags::from_signedness(T::IS_SIGNED),
        )
        .expect("internal error, overflow computation was not returned as was requested")
    }

    pub(crate) fn propagate_single_carry_parallelized(&self, radix: &mut [Ciphertext]) {
        self.advanced_add_assign_with_carry_at_least_4_bits(
            radix,
            &[],
            None,
            ComputationFlags::None,
        );
    }

    pub(crate) fn advanced_add_assign_with_carry(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: ComputationFlags,
    ) -> Option<BooleanBlock> {
        // TODO: estimate by thread count
        if self.message_modulus().0 * self.carry_modulus().0 >= 16 {
            self.advanced_add_assign_with_carry_at_least_4_bits(
                lhs,
                rhs,
                input_carry,
                requested_flag,
            )
        } else {
            self.advanced_add_assign_with_carry_sequential(lhs, rhs, input_carry, requested_flag)
        }
    }

    pub(crate) fn advanced_add_assign_with_carry_sequential(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: ComputationFlags,
    ) -> Option<BooleanBlock> {
        assert_eq!(
            lhs.len(),
            rhs.len(),
            "Both operands must have the same number of blocks"
        );

        if lhs.is_empty() {
            return if requested_flag == ComputationFlags::None {
                None
            } else {
                Some(self.create_trivial_boolean_block(false))
            };
        }

        let mut carry = input_carry.map_or_else(
            || self.key.create_trivial(0),
            |boolean_block| boolean_block.0.clone(),
        );

        // 2_2, 3_3, 4_4
        // If we have at least 2 bits and at least as much carries
        if self.key.message_modulus.0 >= 4 && self.key.carry_modulus.0 >= self.key.message_modulus.0
        {
            let mut overflow_flag = if requested_flag == ComputationFlags::Overflow {
                let mut block = self.key.unchecked_scalar_mul(
                    lhs.last().as_ref().unwrap(),
                    self.message_modulus().0 as u8,
                );
                self.key
                    .unchecked_add_assign(&mut block, rhs.last().as_ref().unwrap());
                Some(block)
            } else {
                None
            };
            // Handle the first block
            self.key.unchecked_add_assign(&mut lhs[0], &rhs[0]);
            self.key.unchecked_add_assign(&mut lhs[0], &carry);

            // To be able to use carry_extract_assign in it
            carry.clone_from(&lhs[0]);
            rayon::scope(|s| {
                s.spawn(|_| {
                    self.key.message_extract_assign(&mut lhs[0]);
                });

                s.spawn(|_| {
                    self.key.carry_extract_assign(&mut carry);
                });

                if requested_flag == ComputationFlags::Overflow {
                    s.spawn(|_| {
                        // Computing the overflow flag requires and extra step for the first block

                        let overflow_flag = overflow_flag.as_mut().unwrap();
                        let num_bits_in_message = self.message_modulus().0.ilog2() as u64;
                        let lut = self.key.generate_lookup_table(|lhs_rhs| {
                            let lhs = lhs_rhs / self.message_modulus().0 as u64;
                            let rhs = lhs_rhs % self.message_modulus().0 as u64;
                            let mask = (1 << (num_bits_in_message - 1)) - 1;
                            let lhs_except_last_bit = lhs & mask;
                            let rhs_except_last_bit = rhs & mask;

                            let overflows_with_given_input_carry = |input_carry| {
                                let output_carry =
                                    ((lhs + rhs + input_carry) >> num_bits_in_message) & 1;

                                let input_carry_to_last_bit =
                                    ((lhs_except_last_bit + rhs_except_last_bit + input_carry)
                                        >> (num_bits_in_message - 1))
                                        & 1;

                                u64::from(input_carry_to_last_bit != output_carry)
                            };

                            (overflows_with_given_input_carry(1) << 3)
                                | (overflows_with_given_input_carry(0) << 2)
                        });
                        self.key.apply_lookup_table_assign(overflow_flag, &lut);
                    });
                }
            });

            let num_blocks = lhs.len();
            for (lhs_b, rhs_b) in lhs[1..num_blocks - 1]
                .iter_mut()
                .zip(rhs[1..num_blocks - 1].iter())
            {
                self.key.unchecked_add_assign(lhs_b, rhs_b);
                self.key.unchecked_add_assign(lhs_b, &carry);

                carry.clone_from(lhs_b);
                rayon::join(
                    || self.key.message_extract_assign(lhs_b),
                    || self.key.carry_extract_assign(&mut carry),
                );
            }

            // Handle the last block
            self.key.unchecked_add_assign(&mut lhs[0], &rhs[0]);
            self.key.unchecked_add_assign(&mut lhs[0], &carry);

            if let Some(block) = overflow_flag.as_mut() {
                self.key.unchecked_add_assign(block, &carry);
            }

            // To be able to use carry_extract_assign in it
            carry.clone_from(&lhs[0]);

            rayon::scope(|s| {
                s.spawn(|_| {
                    self.key.message_extract_assign(&mut lhs[0]);
                });

                s.spawn(|_| {
                    self.key.carry_extract_assign(&mut carry);
                });

                if requested_flag == ComputationFlags::Overflow {
                    s.spawn(|_| {
                        let overflow_flag_block = overflow_flag.as_mut().unwrap();
                        //let shifted_carry = self.key.unchecked_scalar_mul(&carry, 2);
                        // Computing the overflow flag requires and extra step for the first block
                        let overflow_flag_lut = self.key.generate_lookup_table(|block| {
                            let input_carry = block & 1;
                            if input_carry == 1 {
                                (block >> 3) & 1
                            } else {
                                (block >> 2) & 1
                            }
                        });

                        self.key
                            .apply_lookup_table_assign(overflow_flag_block, &overflow_flag_lut);
                    });
                }
            });

            return match requested_flag {
                ComputationFlags::None => None,
                ComputationFlags::Overflow => {
                    assert!(
                        overflow_flag.is_some(),
                        "internal error, overflow_flag should exist"
                    );
                    overflow_flag.map(BooleanBlock::new_unchecked)
                }
                ComputationFlags::Carry => {
                    carry.degree = Degree::new(1);
                    Some(BooleanBlock::new_unchecked(carry))
                }
            };
        }

        // 1_X parameters
        //
        // Same idea as other algorithms, however since we have 1 bit per block
        // we do not have to resolve any inner propagation but it adds one more
        // sequential PBS
        if self.key.message_modulus.0 == 2 {
            fn block_add_assign_returning_carry(
                sks: &ServerKey,
                lhs: &mut Ciphertext,
                rhs: &Ciphertext,
                carry: &Ciphertext,
            ) -> Ciphertext {
                sks.key.unchecked_add_assign(lhs, rhs);
                sks.key.unchecked_add_assign(lhs, carry);
                let (carry, message) = rayon::join(
                    || sks.key.carry_extract(lhs),
                    || sks.key.message_extract(lhs),
                );

                *lhs = message;

                carry
            }
            let num_blocks = lhs.len();
            for (lhs_b, rhs_b) in lhs[..num_blocks - 1]
                .iter_mut()
                .zip(rhs[..num_blocks - 1].iter())
            {
                carry = block_add_assign_returning_carry(self, lhs_b, rhs_b, &carry);
            }

            let mut output_carry = block_add_assign_returning_carry(
                self,
                &mut lhs[num_blocks - 1],
                &rhs[num_blocks - 1],
                &carry,
            );

            return match requested_flag {
                ComputationFlags::None => None,
                ComputationFlags::Overflow => {
                    let overflowed = self.key.not_equal(&output_carry, &carry);
                    Some(BooleanBlock::new_unchecked(overflowed))
                }
                ComputationFlags::Carry => {
                    output_carry.degree = Degree::new(1);
                    Some(BooleanBlock::new_unchecked(output_carry))
                }
            };
        }

        panic!(
            "Invalid combo of message modulus ({}) and carry modulus ({}) \n\
            This function requires the message modulus >= 2 and carry modulus >= message_modulus \n\
            I.e. PARAM_MESSAGE_X_CARRY_Y where X >= 1 and Y >= X.",
            self.key.message_modulus.0, self.key.carry_modulus.0
        );
    }

    /// Does lhs += (rhs + carry)
    /// acts like the ADC assemby op, expect, the flags have to be explicitely requested
    /// as they incur additional PBS
    fn advanced_add_assign_with_carry_at_least_4_bits(
        &self,
        lhs: &mut [Ciphertext],
        rhs: &[Ciphertext],
        input_carry: Option<&BooleanBlock>,
        requested_flag: ComputationFlags,
    ) -> Option<BooleanBlock> {
        // Empty rhs is a specially allowed 'weird' case to have
        // act like a 'propagate single carry' function
        if rhs.is_empty() {
            // Techinically, CarryFlag is computable, but OverflowFlag is not
            assert_eq!(requested_flag, ComputationFlags::None);
        } else {
            assert_eq!(
                lhs.len(),
                rhs.len(),
                "Both operands must have the same number of blocks"
            );
        }

        if lhs.is_empty() {
            // Then both are empty
            if requested_flag == ComputationFlags::None {
                return None;
            }
            return Some(self.create_trivial_boolean_block(false));
        }

        let saved_last_blocks = if requested_flag == ComputationFlags::Overflow {
            Some((lhs.last().cloned().unwrap(), rhs.last().cloned().unwrap()))
        } else {
            None
        };

        // Perform the block additions
        for (lhs_b, rhs_b) in lhs.iter_mut().zip(rhs.iter()) {
            self.key.unchecked_add_assign(lhs_b, rhs_b);
        }
        if let Some(carry) = input_carry {
            self.key.unchecked_add_assign(&mut lhs[0], &carry.0);
        }

        let blocks = lhs;
        let num_blocks = blocks.len();

        let message_modulus = self.message_modulus().0 as u64;
        let num_bits_in_message = message_modulus.ilog2() as u64;

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        let grouping_size = num_bits_in_block as usize;

        let num_groupings = num_blocks.div_ceil(grouping_size);
        assert!(self.key.max_noise_level.get() >= grouping_size);

        let num_carry_to_resolve = num_groupings - 1;

        let sequential_depth = (num_carry_to_resolve as u32 - 1) / (grouping_size as u32 - 1);
        let hillis_steel_depth = if num_carry_to_resolve == 0 {
            0
        } else {
            num_carry_to_resolve.ceil_ilog2()
        };

        let shift_grouping_pgn = sequential_depth <= hillis_steel_depth;

        let mut output_flag = None;

        // First step
        let (shifted_blocks, block_states) = match requested_flag {
            ComputationFlags::None => {
                let (shifted_blocks, mut block_states) =
                    self.compute_shifted_blocks_and_block_states(blocks);
                let _ = block_states.pop().unwrap();
                (shifted_blocks, block_states)
            }
            ComputationFlags::Overflow => {
                let (block, (shifted_blocks, block_states)) = rayon::join(
                    || {
                        let lut = self.key.generate_lookup_table_bivariate(|lhs, rhs| {
                            let mask = (1 << (num_bits_in_message - 1)) - 1;
                            let lhs_except_last_bit = lhs & mask;
                            let rhs_except_last_bit = rhs & mask;

                            let overflows_with_given_input_carry = |input_carry| {
                                let output_carry =
                                    ((lhs + rhs + input_carry) >> num_bits_in_message) & 1;

                                let input_carry_to_last_bit =
                                    ((lhs_except_last_bit + rhs_except_last_bit + input_carry)
                                        >> (num_bits_in_message - 1))
                                        & 1;

                                u64::from(input_carry_to_last_bit != output_carry)
                            };

                            (overflows_with_given_input_carry(1) << 3)
                                | (overflows_with_given_input_carry(0) << 2)
                        });
                        let (last_lhs_block, last_rhs_block) = saved_last_blocks.as_ref().unwrap();
                        self.key.unchecked_apply_lookup_table_bivariate(
                            last_lhs_block,
                            last_rhs_block,
                            &lut,
                        )
                    },
                    || {
                        let (shifted_blocks, mut block_states) =
                            self.compute_shifted_blocks_and_block_states(blocks);
                        let _ = block_states.pop().unwrap();
                        (shifted_blocks, block_states)
                    },
                );

                output_flag = Some(block);
                (shifted_blocks, block_states)
            }
            ComputationFlags::Carry => {
                let (shifted_blocks, mut block_states) =
                    self.compute_shifted_blocks_and_block_states(blocks);
                let last_block_state = block_states.pop().unwrap();
                output_flag = Some(last_block_state);
                (shifted_blocks, block_states)
            }
        };

        // Second step
        let (mut prepared_blocks, mut groupings_pgns) = {
            // This stores, the LUTs that given a cum sum block in the first grouping
            // tells if a carry is generated or not
            let first_grouping_inner_propagation_luts = (0..grouping_size - 1)
                .map(|index| {
                    self.key.generate_lookup_table(|propa_cum_sum_block| {
                        let carry = propa_cum_sum_block & (1 << index);
                        if carry != 0 {
                            2 // Generates
                        } else {
                            0 // Nothing
                        }
                    })
                })
                .collect::<Vec<_>>();

            // This stores, the LUTs that given a cum sum in non first grouping
            // tells if a carry is generated or propagated or neither of these
            let other_groupings_inner_propagation_luts = (0..grouping_size)
                .map(|index| {
                    self.key.generate_lookup_table(|propa_cum_sum_block| {
                        let mask = (2 << index) - 1;
                        if propa_cum_sum_block >= (2 << index) {
                            2 // Generates
                        } else if (propa_cum_sum_block & mask) == mask {
                            1 // Propagate
                        } else {
                            0
                        }
                    })
                })
                .collect::<Vec<_>>();

            // This stores the LUT that outputs the propagation result of the first grouping
            let first_grouping_outer_propagation_lut = self.key.generate_lookup_table(|block| {
                // Check if the last bit of the block is set
                (block >> (num_bits_in_block - 1)) & 1
            });

            // This stores the LUTs that output the propagation result of the other groupings
            let grouping_chunk_pgn_luts = if shift_grouping_pgn {
                // When using the sequential algorithm for the propagation of one grouping to the
                // other we need to shift the PGN state to the correct position, so we later, when
                // using them only lwe_add is needed and so noise management is easy
                //
                // Also, these LUTs are 'negacylic', they are made to exploit the padding bit
                // resulting blocks from these LUTs must be added the constant `1 << index`.
                (0..grouping_size - 1)
                    .map(|i| {
                        self.key.generate_lookup_table(|block| {
                            // All bits set to 1 (e.g. 0b1111), means propagate
                            if block == (block_modulus - 1) as u64 {
                                0
                            } else {
                                // u64::MAX is -1 in tow's complement
                                // We apply the modulus including the padding bit
                                (u64::MAX << i) % (1 << (num_bits_in_block + 1))
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            } else {
                // This LUT is for when we are using Hillis-Steele prefix-scan to propagate carries
                // between groupings. When using this propagation, the encoding of the states
                // are a bit different.
                //
                // Also, these LUTs are 'negacylic', they are made to exploit the padding bit
                // resulting blocks from these LUTs must be added the constant `1`.
                vec![self.key.generate_lookup_table(|block| {
                    if block == (block_modulus - 1) as u64 {
                        // All bits set to 1 (e.g. 0b1111), means propagate
                        2
                    } else {
                        // u64::MAX is -1 in tow's complement
                        // We apply the modulus including the padding bit
                        u64::MAX % (1 << (block_modulus + 1))
                    }
                })]
            };

            let mut propagation_cum_sums = Vec::with_capacity(num_blocks);
            block_states.chunks(grouping_size).for_each(|grouping| {
                propagation_cum_sums.push(grouping[0].clone());
                for other in &grouping[1..] {
                    let mut result = other.clone();
                    self.key
                        .unchecked_add_assign(&mut result, propagation_cum_sums.last().unwrap());

                    propagation_cum_sums.push(result);
                }
            });

            let len = propagation_cum_sums.len();
            propagation_cum_sums
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, cum_sum_block)| {
                    let grouping_index = i / grouping_size;
                    let is_in_first_grouping = grouping_index == 0;
                    let index_in_grouping = i % (grouping_size);

                    let lut = if is_in_first_grouping {
                        //println!("drjredd");
                        if index_in_grouping == grouping_size - 1 {
                            //println!("First Grouping PGN");
                            &first_grouping_outer_propagation_lut
                        } else {
                            &first_grouping_inner_propagation_luts[index_in_grouping]
                        }
                    } else if index_in_grouping == grouping_size - 1 {
                        if shift_grouping_pgn {
                            //println!("Grouping PGN for sequential");
                            &grouping_chunk_pgn_luts[(grouping_index - 1) % (grouping_size - 1)]
                        } else {
                            //println!("Grouping PGN for hillis");
                            &grouping_chunk_pgn_luts[0]
                        }
                    } else {
                        &other_groupings_inner_propagation_luts[index_in_grouping]
                    };

                    self.key.apply_lookup_table_assign(cum_sum_block, lut);

                    let may_have_its_padding_bit_set =
                        !is_in_first_grouping && index_in_grouping == grouping_size - 1;
                    if may_have_its_padding_bit_set {
                        if shift_grouping_pgn {
                            self.key.unchecked_scalar_add_assign(
                                cum_sum_block,
                                1 << ((grouping_index - 1) % (grouping_size - 1)),
                            );
                        } else {
                            self.key.unchecked_scalar_add_assign(cum_sum_block, 1);
                        }
                        cum_sum_block.degree = Degree::new(message_modulus as usize - 1);
                    }
                    //("cumsum out ", &[cum_sum_block.clone()]);
                });

            let num_groupings = num_blocks / grouping_size;
            let mut groupings_pgns = Vec::with_capacity(num_groupings);
            let mut propagation_simulators = Vec::with_capacity(num_blocks);

            // First block does not get borrowed from
            propagation_simulators.push(self.key.create_trivial(0));
            for (i, block) in propagation_cum_sums
                // .drain(..propagation_cum_sums.len().saturating_sub(1))
                .drain(..)
                .enumerate()
            {
                if propagation_simulators.len() % grouping_size == 0 {
                    groupings_pgns.push(block);
                    if i != len - 1 {
                        // The first block in each grouping has its simulator set to 0
                        // because it always receives any input borrow that may be generated from
                        // previous grouping
                        propagation_simulators.push(self.key.create_trivial(1));
                    }
                } else {
                    propagation_simulators.push(block);
                }
            }

            let mut prepared_blocks = shifted_blocks;
            prepared_blocks
                .iter_mut()
                .zip(propagation_simulators.iter())
                .for_each(|(block, simulator)| {
                    crate::core_crypto::algorithms::lwe_ciphertext_add_assign(
                        &mut block.ct,
                        &simulator.ct,
                    );
                });

            match requested_flag {
                ComputationFlags::None => {}
                ComputationFlags::Overflow => {
                    let block = output_flag.as_mut().unwrap();
                    self.key
                        .unchecked_add_assign(block, &propagation_simulators[num_blocks - 1]);
                }
                ComputationFlags::Carry => {
                    let block = output_flag.as_mut().unwrap();
                    self.key
                        .unchecked_add_assign(block, &propagation_simulators[num_blocks - 1]);
                }
            }

            (prepared_blocks, groupings_pgns)
        };

        // Third step: resolving carry propagation between the groups
        let resolved_carries = if groupings_pgns.is_empty() {
            vec![self.key.create_trivial(0)]
        } else if shift_grouping_pgn {
            let luts = (0..grouping_size - 1)
                .map(|index| {
                    self.key.generate_lookup_table(|propa_cum_sum_block| {
                        let carry = propa_cum_sum_block & (1 << (index + 1));
                        u64::from(carry != 0)
                    })
                })
                .collect::<Vec<_>>();

            groupings_pgns.rotate_left(1);
            let mut resolved_carries =
                vec![self.key.create_trivial(0), groupings_pgns.pop().unwrap()];
            for chunk in groupings_pgns.chunks(grouping_size - 1) {
                //println!("chunk size: {}", chunk.len());
                let mut cum_sums = chunk.to_vec();
                self.key
                    .unchecked_add_assign(&mut cum_sums[0], resolved_carries.last().unwrap());

                for i in [1, 2] {
                    if i == 1 && cum_sums.len() < 2 {
                        continue;
                    }
                    if i == 2 && cum_sums.len() < 3 {
                        continue;
                    }
                    // All this just to do add_assign(&mut cum_sum[i], &cum_sum[i-1])
                    let (l, r) = cum_sums.split_at_mut(i);
                    let llen = l.len();
                    self.key.unchecked_add_assign(&mut r[0], &l[llen - 1]);
                }

                cum_sums
                    .par_iter_mut()
                    .zip(luts.par_iter())
                    .for_each(|(cum_sum_block, lut)| {
                        self.key.apply_lookup_table_assign(cum_sum_block, lut);
                    });

                // Cum sums now contains the output carries
                resolved_carries.append(&mut cum_sums);
            }

            resolved_carries
        } else {
            let lut_carry_propagation_sum =
                self.key
                    .generate_lookup_table_bivariate(|msb: u64, lsb: u64| -> u64 {
                        if msb == 2 {
                            1 // Remap Generate to 1
                        } else if msb == 3 {
                            // MSB propagates
                            if lsb == 2 {
                                1
                            } else {
                                lsb
                            } // also remap here
                        } else {
                            msb
                        }
                    });
            let sum_function = |block_borrow: &mut Ciphertext,
                                previous_block_borrow: &Ciphertext| {
                self.key.unchecked_apply_lookup_table_bivariate_assign(
                    block_borrow,
                    previous_block_borrow,
                    &lut_carry_propagation_sum,
                );
            };
            let mut resolved_carries =
                self.compute_prefix_sum_hillis_steele(groupings_pgns, sum_function);
            resolved_carries.insert(0, self.key.create_trivial(0));
            resolved_carries
        };

        // Final step: adding resolved carries and cleaning result
        let mut add_carries_and_cleanup = || {
            let message_extract_lut = self
                .key
                .generate_lookup_table(|block| (block >> 1) % message_modulus);

            prepared_blocks
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let grouping_index = i / grouping_size;
                    let borrow = &resolved_carries[grouping_index];
                    crate::core_crypto::algorithms::lwe_ciphertext_add_assign(
                        &mut block.ct,
                        &borrow.ct,
                    );

                    self.key
                        .apply_lookup_table_assign(block, &message_extract_lut)
                });
        };

        match requested_flag {
            ComputationFlags::None => {
                add_carries_and_cleanup();
            }
            ComputationFlags::Overflow => {
                let overflow_flag_lut = self.key.generate_lookup_table(|block| {
                    let input_carry = (block >> 1) & 1;
                    if input_carry == 1 {
                        (block >> 3) & 1
                    } else {
                        (block >> 2) & 1
                    }
                });
                rayon::join(
                    || {
                        let block = output_flag.as_mut().unwrap();
                        self.key.unchecked_add_assign(
                            block,
                            &resolved_carries[resolved_carries.len() - 1],
                        );
                        self.key
                            .apply_lookup_table_assign(block, &overflow_flag_lut);
                    },
                    add_carries_and_cleanup,
                );
            }
            ComputationFlags::Carry => {
                let carry_flag_lut = self.key.generate_lookup_table(|block| (block >> 2) & 1);

                rayon::join(
                    || {
                        let block = output_flag.as_mut().unwrap();
                        self.key.unchecked_add_assign(
                            block,
                            &resolved_carries[resolved_carries.len() - 1],
                        );
                        self.key.apply_lookup_table_assign(block, &carry_flag_lut);
                    },
                    add_carries_and_cleanup,
                );
            }
        }

        blocks.clone_from_slice(&prepared_blocks);

        match requested_flag {
            ComputationFlags::None => None,
            ComputationFlags::Overflow | ComputationFlags::Carry => {
                output_flag.map(BooleanBlock::new_unchecked)
            }
        }
    }

    fn compute_shifted_blocks_and_block_states(
        &self,
        blocks: &[Ciphertext],
    ) -> (Vec<Ciphertext>, Vec<Ciphertext>) {
        let num_blocks = blocks.len();

        let message_modulus = self.message_modulus().0 as u64;

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        let grouping_size = num_bits_in_block as usize;

        let shift_block_fn = |block| (block % message_modulus) << 1;
        let mut first_grouping_luts = vec![{
            let first_block_state_fn = |block| {
                if block >= message_modulus {
                    1 // Generates
                } else {
                    0 // Nothing
                }
            };
            self.key
                .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
        }];
        for i in 1..grouping_size {
            let state_fn = |block| {
                let r = if block >= message_modulus {
                    2 // Generates Carry
                } else if block == message_modulus - 1 {
                    1 // Propagates a carry
                } else {
                    0 // Does not borrow
                };

                r << (i - 1)
            };
            first_grouping_luts.push(
                self.key
                    .generate_many_lookup_table(&[&state_fn, &shift_block_fn]),
            );
        }

        let other_block_state_luts = (0..grouping_size)
            .map(|i| {
                let state_fn = |block| {
                    let r = if block >= message_modulus {
                        2 // Generates Carry
                    } else if block == message_modulus - 1 {
                        1 // Propagates a carry
                    } else {
                        0 // Does not borrow
                    };

                    r << i
                };
                self.key
                    .generate_many_lookup_table(&[&state_fn, &shift_block_fn])
            })
            .collect::<Vec<_>>();

        let last_block_luts = {
            if blocks.len() == 1 {
                let first_block_state_fn = |block| {
                    if block >= message_modulus {
                        2 << 1 // Generates
                    } else {
                        0 // Nothing
                    }
                };
                self.key
                    .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
            } else if (blocks.len() - 1) <= grouping_size {
                // The last block is in the first grouping
                first_grouping_luts[2].clone()
            } else {
                first_grouping_luts[2].clone()
            }
        };

        let tmp = blocks
            .par_iter()
            .enumerate()
            .map(|(index, block)| {
                let grouping_index = index / grouping_size;
                let is_in_first_grouping = grouping_index == 0;
                let index_in_grouping = index % (grouping_size);
                let is_last_index = index == blocks.len() - 1;

                let luts = if is_last_index {
                    &last_block_luts
                } else if is_in_first_grouping {
                    &first_grouping_luts[index_in_grouping]
                } else {
                    &other_block_state_luts[index_in_grouping]
                };
                self.key.apply_many_lookup_table(block, luts)
            })
            .collect::<Vec<_>>();

        let mut shifted_blocks = Vec::with_capacity(num_blocks);
        let mut block_states = Vec::with_capacity(num_blocks);
        for mut blocks in tmp {
            assert_eq!(blocks.len(), 2);
            shifted_blocks.push(blocks.pop().unwrap());
            block_states.push(blocks.pop().unwrap());
        }

        (shifted_blocks, block_states)
    }

    /// Computes a prefix sum/scan in parallel using Hillis & Steel algorithm
    pub(crate) fn compute_prefix_sum_hillis_steele<F>(
        &self,
        mut blocks: Vec<Ciphertext>,
        sum_function: F,
    ) -> Vec<Ciphertext>
    where
        F: for<'a, 'b> Fn(&'a mut Ciphertext, &'b Ciphertext) + Sync,
    {
        debug_assert!(self.key.message_modulus.0 * self.key.carry_modulus.0 >= (1 << 4));

        if blocks.is_empty() || blocks.len() == 1 {
            return blocks;
        }

        let num_blocks = blocks.len();
        let num_steps = blocks.len().ceil_ilog2() as usize;

        let mut space = 1;
        let mut step_output = blocks.clone();
        for _ in 0..num_steps {
            step_output[space..num_blocks]
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let prev_block_carry = &blocks[i];
                    sum_function(block, prev_block_carry);
                });
            for i in space..num_blocks {
                blocks[i].clone_from(&step_output[i]);
            }

            space *= 2;
        }

        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::should_hillis_steele_propagation_be_faster;
    use crate::integer::gen_keys_radix;
    use crate::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    #[test]
    fn test_propagate_single_carry_on_empty_input_ci_run_filter() {
        // Parameters and num blocks do not matter here
        let (_, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);

        sks.propagate_single_carry_parallelized(&mut []);
        // The most interesting part we test is that the code does not panic
    }

    #[test]
    fn test_hillis_steele_choice_128_threads() {
        // m6i.metal like number of threads
        const NUM_THREADS: usize = 128;
        // 16, 32, 64, 128, 256 512 bits
        for num_blocks in [8, 16, 32, 64, 128, 256] {
            assert!(
                should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
        // 8 bits
        assert!(!should_hillis_steele_propagation_be_faster(4, NUM_THREADS),);
    }

    #[test]
    fn test_hillis_steele_choice_12_threads() {
        const NUM_THREADS: usize = 12;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }

    #[test]
    fn test_hillis_steele_choice_8_threads() {
        const NUM_THREADS: usize = 8;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }

    #[test]
    fn test_hillis_steele_choice_4_threads() {
        const NUM_THREADS: usize = 4;
        // 8, 16, 32, 64, 128, 256, 512 bits
        for num_blocks in [4, 8, 16, 32, 64, 128, 256] {
            assert!(
                !should_hillis_steele_propagation_be_faster(num_blocks, NUM_THREADS),
                "Expected hillis and steele to *not* be chosen for {num_blocks} blocks and {NUM_THREADS} threads"
            );
        }
    }
}
