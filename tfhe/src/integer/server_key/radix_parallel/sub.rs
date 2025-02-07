use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix_parallel::add::CarryPropagationAlgorithm;
use crate::integer::server_key::radix_parallel::OutputFlag;
use crate::integer::{
    BooleanBlock, IntegerCiphertext, RadixCiphertext, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::Ciphertext;
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.smart_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);

        result
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.smart_sub_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_assign_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }
        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

        self.unchecked_sub_assign(ctxt_left, ctxt_right);
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub_parallelized<T>(&self, ctxt_left: &T, ctxt_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ctxt_left.clone();
        self.sub_assign_parallelized(&mut ct_res, ctxt_right);
        ct_res
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.sub_assign_parallelized(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub_assign_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ctxt_left);
                (ctxt_left, ctxt_right)
            }
            (false, false) => {
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ctxt_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ctxt_left, &tmp_rhs)
            }
        };

        let neg = self.unchecked_neg(rhs);
        self.advanced_add_assign_with_carry_parallelized(
            lhs.blocks_mut(),
            neg.blocks(),
            None,
            OutputFlag::None,
            CarryPropagationAlgorithm::Automatic,
        );
    }

    /// Computes the subtraction and returns an indicator of overflow
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg_1 = 1u8;
    /// let msg_2 = 255u8;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction
    /// let (result, overflowed) = sks.unsigned_overflowing_sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let decrypted_result: u8 = cks.decrypt(&result);
    /// let decrypted_overflow = cks.decrypt_bool(&overflowed);
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn unsigned_overflowing_sub_parallelized(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ctxt_left.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, ctxt_right)
            }
            (false, false) => {
                tmp_lhs = ctxt_left.clone();
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_unsigned_overflowing_sub_parallelized(lhs, rhs)
    }

    pub fn unchecked_unsigned_overflowing_sub_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );

        const INPUT_BORROW: Option<&BooleanBlock> = None;
        const COMPUTE_OVERFLOW: bool = true;

        let mut result = lhs.clone();
        let overflowed =
            if self.is_eligible_for_parallel_single_carry_propagation(lhs.blocks.len()) {
                self.advanced_sub_assign_with_borrow_parallelized_at_least_4_bits(
                    &mut result,
                    rhs,
                    INPUT_BORROW,
                    COMPUTE_OVERFLOW,
                )
            } else {
                self.advanced_sub_assign_with_borrow_sequential(
                    &mut result,
                    rhs,
                    INPUT_BORROW,
                    COMPUTE_OVERFLOW,
                )
            }
            .expect("overflow computation was requested");

        (result, overflowed)
    }

    /// Does lhs -= (rhs + carry)
    ///
    /// - Parameters must have at least 2 bits of message, 2 bits of carry
    /// - blocks of lhs and rhs must be clean (no carries)
    /// - lhs and rhs must have the same length
    pub(crate) fn advanced_sub_assign_with_borrow_parallelized_at_least_4_bits(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &RadixCiphertext,
        input_borrow: Option<&BooleanBlock>,
        compute_overflow: bool,
    ) -> Option<BooleanBlock> {
        // Note: we could, as is done is advanced_add_assign_with_carry
        // compute either the overflow flag or the borrow flag as the user request
        // but as the overflow flag is not needed in the code base, we simply only
        // compute the borrow flag if requested.
        //
        // This is why the inputs are RadixCiphertext rather than &[Ciphertext]

        let lhs = &mut lhs.blocks;
        let rhs = &rhs.blocks;

        assert_eq!(
            lhs.len(),
            rhs.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.len(),
            rhs.len()
        );

        if lhs.is_empty() {
            // Then both are empty
            if compute_overflow {
                return Some(self.create_trivial_boolean_block(false));
            }
            return None;
        }

        for (lhs_b, rhs_b) in lhs.iter_mut().zip(rhs.iter()) {
            self.key.unchecked_sub_assign(lhs_b, rhs_b);
        }
        if let Some(borrow) = input_borrow {
            self.key.unchecked_sub_assign(&mut lhs[0], &borrow.0);
        }

        // First step
        let (shifted_blocks, mut block_states) =
            self.compute_shifted_blocks_and_block_borrow_states(lhs);

        // The propagation state of the last block will be used to determine
        // if overflow occurs (i.e is there an output borrow)
        let mut overflow_block = block_states.pop().unwrap();

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        // Just in case we compare with max noise level, but it should always be num_bits_in_blocks
        // with the parameters we provide
        let grouping_size =
            (num_bits_in_block as usize).min(self.key.max_noise_level.get() as usize);

        // Second step
        let (mut prepared_blocks, resolved_borrows) = {
            let (propagation_simulators, resolved_borrows) = self
                .compute_propagation_simulators_and_groups_carries(grouping_size, &block_states);

            let mut prepared_blocks = shifted_blocks;
            prepared_blocks
                .iter_mut()
                .zip(propagation_simulators.iter())
                .for_each(|(block, simulator)| {
                    // simulator may have either of these value
                    // '2' if the block is borrowed from
                    // '1' if the block will be borrowed from if the group it belongs to receive a
                    //     borrow
                    // '0' if the block will absorb any potential borrow
                    //
                    // What we do is we subtract this value from the block, as it's a borrow, not a
                    // carry, and we add one, this means:
                    //
                    // '(-2 + 1) ==  -1' We remove one if the block was meant to receive a borrow
                    // '(-1 + 1) ==  -0' The block won't change, which means that when subtracting
                    // the borrow (value: 1 or 0) that the group receives, its correctly applied
                    // i.e the propagation simulation will be correctly done
                    // '(-0 + 1) ==  +1' we add one, meaning that if the block receives a borrow,
                    // we would remove one from the block, which would be absorbed by the 1 we just
                    // added
                    crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                        &mut block.ct,
                        &simulator.ct,
                    );
                    block.set_noise_level(
                        block.noise_level() + simulator.noise_level(),
                        self.key.max_noise_level,
                    );
                    self.key.unchecked_scalar_add_assign(block, 1);
                });

            if compute_overflow {
                self.key.unchecked_add_assign(
                    &mut overflow_block,
                    propagation_simulators.last().unwrap(),
                );
            }

            (prepared_blocks, resolved_borrows)
        };

        let mut subtract_borrow_and_cleanup_prepared_blocks = || {
            let message_extract_lut = self
                .key
                .generate_lookup_table(|block| (block >> 1) % self.message_modulus().0);

            prepared_blocks
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, block)| {
                    let grouping_index = i / grouping_size;
                    let borrow = &resolved_borrows[grouping_index];
                    crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                        &mut block.ct,
                        &borrow.ct,
                    );
                    block.set_noise_level(
                        block.noise_level() + borrow.noise_level(),
                        self.key.max_noise_level,
                    );

                    self.key
                        .apply_lookup_table_assign(block, &message_extract_lut)
                });
        };

        // Final step
        if compute_overflow {
            rayon::join(subtract_borrow_and_cleanup_prepared_blocks, || {
                let borrow_flag_lut = self.key.generate_lookup_table(|block| (block >> 2) & 1);
                self.key.unchecked_add_assign(
                    &mut overflow_block,
                    &resolved_borrows[resolved_borrows.len() - 1],
                );
                self.key
                    .apply_lookup_table_assign(&mut overflow_block, &borrow_flag_lut);
            });
        } else {
            subtract_borrow_and_cleanup_prepared_blocks();
        }

        lhs.clone_from_slice(&prepared_blocks);

        if compute_overflow {
            Some(BooleanBlock::new_unchecked(overflow_block))
        } else {
            None
        }
    }

    /// blocks must be the result of (left_block - right_block + message_modulus)
    /// (just like shortint::unchecked_sub_assign does on clean (no carries) ciphertext
    fn compute_shifted_blocks_and_block_borrow_states(
        &self,
        blocks: &[Ciphertext],
    ) -> (Vec<Ciphertext>, Vec<Ciphertext>) {
        let num_blocks = blocks.len();

        let message_modulus = self.message_modulus().0;

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();

        let grouping_size = num_bits_in_block as usize;

        let shift_block_fn = |block| {
            let overflow_guard = message_modulus;
            let block = block % message_modulus;
            (overflow_guard | block) << 1
        };
        let mut first_grouping_luts = vec![{
            let first_block_state_fn = |block| {
                if block < message_modulus {
                    1 // Borrows
                } else {
                    0 // Nothing
                }
            };
            self.key
                .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
        }];
        for i in 1..grouping_size {
            let state_fn = |block| {
                #[allow(clippy::comparison_chain)]
                let r = if block < message_modulus {
                    2 // Borrows
                } else if block == message_modulus {
                    1 // Propagates a borrow
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
                    #[allow(clippy::comparison_chain)]
                    let r = if block < message_modulus {
                        2 // Generates borrow
                    } else if block == message_modulus {
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

        // For the last block we do something a bit different because the
        // state we compute will be used (if needed) to compute the output borrow
        // of the whole subtraction. And this computation will be done during the 'cleaning'
        // phase
        let last_block_luts = {
            if blocks.len() == 1 {
                let first_block_state_fn = |block| {
                    if block < message_modulus {
                        2 << 1 // Generates a borrow
                    } else {
                        0 // Nothing
                    }
                };
                self.key
                    .generate_many_lookup_table(&[&first_block_state_fn, &shift_block_fn])
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

    pub(crate) fn advanced_sub_assign_with_borrow_sequential(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &RadixCiphertext,
        input_borrow: Option<&BooleanBlock>,
        compute_overflow: bool,
    ) -> Option<BooleanBlock> {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );

        let modulus = self.key.message_modulus.0;

        // If the block does not have a carry after the subtraction, it means it needs to
        // borrow from the next block
        let compute_borrow_lut = self
            .key
            .generate_lookup_table(|x| if x < modulus { 1 } else { 0 });

        let mut borrow = input_borrow.map_or_else(|| self.key.create_trivial(0), |b| b.0.clone());
        for (lhs_block, rhs_block) in lhs.blocks.iter_mut().zip(rhs.blocks.iter()) {
            self.key.unchecked_sub_assign(lhs_block, rhs_block);
            // Here unchecked_sub_assign does not give correct result, we don't want
            // the correcting term to be used
            // -> This is ok as the value returned by unchecked_sub is in range
            // 1..(message_mod * 2)
            crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                &mut lhs_block.ct,
                &borrow.ct,
            );
            lhs_block.set_noise_level(
                lhs_block.noise_level() + borrow.noise_level(),
                self.key.max_noise_level,
            );
            let (msg, new_borrow) = rayon::join(
                || self.key.message_extract(lhs_block),
                || self.key.apply_lookup_table(lhs_block, &compute_borrow_lut),
            );
            *lhs_block = msg;
            borrow = new_borrow;
        }

        // borrow of last block indicates overflow
        if compute_overflow {
            Some(BooleanBlock::new_unchecked(borrow))
        } else {
            None
        }
    }

    pub fn unchecked_signed_overflowing_sub_parallelized(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        self.unchecked_signed_overflowing_sub_parallelized_with_choice(
            lhs,
            rhs,
            CarryPropagationAlgorithm::Automatic,
        )
    }

    pub(crate) fn unchecked_signed_overflowing_sub_parallelized_with_choice(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
        algorithm: CarryPropagationAlgorithm,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );

        // We are using two's complement for signed numbers,
        // we do the subtraction by adding the negation of rhs.
        // But to be able to get the correct overflow flag, we need to
        // compute (result, overflow) = (lhs + bitnot(rhs) + 1) instead of
        // (result, overflow) = (lhs + (-rhs). We need the bitnot(rhs) and +1
        // 'separated'
        //
        // Remainder: in two's complement -rhs = bitnot(rhs) + 1
        let flipped_rhs = self.bitnot(rhs);
        let input_carry = self.create_trivial_boolean_block(true);
        let mut result = lhs.clone();
        let overflowed = self
            .advanced_add_assign_with_carry_parallelized(
                result.blocks_mut(),
                flipped_rhs.blocks(),
                Some(&input_carry),
                OutputFlag::Overflow,
                algorithm,
            )
            .expect("internal error, overflow computation was not returned as was requested");
        (result, overflowed)
    }

    /// Computes the subtraction of two signed numbers and returns an indicator of overflow
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg_1 = i8::MIN;
    /// let msg_2 = 1;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt_signed(msg_1);
    /// let ctxt_2 = cks.encrypt_signed(msg_2);
    ///
    /// // Compute homomorphically a subtraction
    /// let (result, overflowed) = sks.signed_overflowing_sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let decrypted_result: i8 = cks.decrypt_signed(&result);
    /// let decrypted_overflow = cks.decrypt_bool(&overflowed);
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn signed_overflowing_sub_parallelized(
        &self,
        ctxt_left: &SignedRadixCiphertext,
        ctxt_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        self.signed_overflowing_sub_parallelized_with_choice(
            ctxt_left,
            ctxt_right,
            CarryPropagationAlgorithm::Automatic,
        )
    }

    pub(crate) fn signed_overflowing_sub_parallelized_with_choice(
        &self,
        ctxt_left: &SignedRadixCiphertext,
        ctxt_right: &SignedRadixCiphertext,
        algorithm: CarryPropagationAlgorithm,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ctxt_left.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, ctxt_right)
            }
            (false, false) => {
                tmp_lhs = ctxt_left.clone();
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_signed_overflowing_sub_parallelized_with_choice(lhs, rhs, algorithm)
    }
}
