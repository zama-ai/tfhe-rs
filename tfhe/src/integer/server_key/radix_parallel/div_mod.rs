use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext, SignedRadixCiphertext};
use crate::integer::server_key::comparator::ZeroComparisonType;
use crate::integer::{IntegerCiphertext, ServerKey};

use crate::shortint::MessageModulus;
use rayon::prelude::*;

impl ServerKey {
    //======================================================================
    //                Div Rem
    //======================================================================
    pub fn unchecked_div_rem_parallelized<T>(&self, numerator: &T, divisor: &T) -> (T, T)
    where
        T: IntegerRadixCiphertext,
    {
        if T::IS_SIGNED {
            let n = SignedRadixCiphertext::from_blocks(numerator.blocks().to_vec());
            let d = SignedRadixCiphertext::from_blocks(divisor.blocks().to_vec());
            let (q, r) = self.signed_unchecked_div_rem_parallelized(&n, &d);
            let q = T::from_blocks(q.into_blocks());
            let r = T::from_blocks(r.into_blocks());
            (q, r)
        } else {
            let n = RadixCiphertext::from_blocks(numerator.blocks().to_vec());
            let d = RadixCiphertext::from_blocks(divisor.blocks().to_vec());
            let (q, r) = self.unsigned_unchecked_div_rem_parallelized(&n, &d);
            let q = T::from_blocks(q.into_blocks());
            let r = T::from_blocks(r.into_blocks());
            (q, r)
        }
    }

    pub fn unchecked_div_rem_floor_parallelized(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let (quotient, remainder) = self.unchecked_div_rem_parallelized(numerator, divisor);

        let (remainder_is_not_zero, remainder_and_divisor_signs_disagrees) = rayon::join(
            || self.unchecked_scalar_ne_parallelized(&remainder, 0),
            || {
                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
                let compare_sign_bits = |x, y| {
                    let x_sign_bit = (x >> sign_bit_pos) & 1;
                    let y_sign_bit = (y >> sign_bit_pos) & 1;
                    u64::from(x_sign_bit != y_sign_bit)
                };
                let lut = self.key.generate_lookup_table_bivariate(compare_sign_bits);
                self.key.unchecked_apply_lookup_table_bivariate(
                    remainder.blocks().last().unwrap(),
                    divisor.blocks().last().unwrap(),
                    &lut,
                )
            },
        );

        let condition = self.key.unchecked_add(
            &remainder_is_not_zero.0,
            &remainder_and_divisor_signs_disagrees,
        );

        let (remainder_plus_divisor, quotient_minus_one) = rayon::join(
            || self.add_parallelized(&remainder, divisor),
            || self.scalar_sub_parallelized(&quotient, 1),
        );

        let (quotient, remainder) = rayon::join(
            || {
                self.unchecked_programmable_if_then_else_parallelized(
                    &condition,
                    &quotient_minus_one,
                    &quotient,
                    |x| x == 2,
                    true,
                )
            },
            || {
                self.unchecked_programmable_if_then_else_parallelized(
                    &condition,
                    &remainder_plus_divisor,
                    &remainder,
                    |x| x == 2,
                    true,
                )
            },
        );

        (quotient, remainder)
    }

    fn unsigned_unchecked_div_rem_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        assert_eq!(
            numerator.blocks.len(),
            divisor.blocks.len(),
            "numerator and divisor must have same number of blocks"
        );
        // Pseudo-code of the school-book / long-division algorithm:
        //
        //
        // div(N/D):
        // Q := 0                  -- Initialize quotient and remainder to zero
        // R := 0
        // for i := n − 1 .. 0 do  -- Where n is number of bits in N
        //   R := R << 1           -- Left-shift R by 1 bit
        //   R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the
        //                         -- numerator
        //   if R ≥ D then
        //     R := R − D
        //     Q(i) := 1
        //   end
        // end
        assert_eq!(
            numerator.blocks.len(),
            divisor.blocks.len(),
            "numerator and divisor must have same number of blocks \
            numerator: {} blocks, divisor: {} blocks",
            numerator.blocks.len(),
            divisor.blocks.len(),
        );
        assert!(
            self.key.message_modulus.0.is_power_of_two(),
            "The message modulus ({}) needs to be a power of two",
            self.key.message_modulus.0
        );
        assert!(
            numerator.block_carries_are_empty(),
            "The numerator must have its carries empty"
        );
        assert!(
            divisor.block_carries_are_empty(),
            "The numerator must have its carries empty"
        );
        assert!(numerator
            .blocks()
            .iter()
            .all(|block| block.message_modulus == self.key.message_modulus
                && block.carry_modulus == self.key.carry_modulus));
        assert!(divisor
            .blocks()
            .iter()
            .all(|block| block.message_modulus == self.key.message_modulus
                && block.carry_modulus == self.key.carry_modulus));

        let num_blocks = numerator.blocks.len();
        let num_bits_in_message = self.key.message_modulus.0.ilog2() as u64;
        let total_bits = num_bits_in_message * num_blocks as u64;

        let mut quotient: RadixCiphertext = self.create_trivial_zero_radix(num_blocks);
        let mut remainder1: RadixCiphertext = self.create_trivial_zero_radix(num_blocks);
        let mut remainder2: RadixCiphertext = self.create_trivial_zero_radix(num_blocks);

        let mut numerator_block_stack = numerator.blocks.clone();

        // The overflow flag is computed by combining 2 separate values,
        // this vec will contain the lut that merges these two flags.
        //
        // Normally only one lut should be needed, and that lut would output a block
        // encrypting 0 or 1.
        // However, since the resulting block would then be left shifted and added to
        // another existing noisy block, we create many LUTs that shift the boolean value
        // to the correct position, to reduce noise growth
        let merge_overflow_flags_luts = (0..num_bits_in_message)
            .map(|bit_position_in_block| {
                self.key.generate_lookup_table_bivariate(|x, y| {
                    u64::from(x == 0 && y == 0) << bit_position_in_block
                })
            })
            .collect::<Vec<_>>();

        for i in (0..total_bits as usize).rev() {
            let block_of_bit = i / num_bits_in_message as usize;
            let pos_in_block = i % num_bits_in_message as usize;

            // i goes from [total_bits - 1 to 0]
            // msb_bit_set goes from [0 to total_bits - 1]
            let msb_bit_set = total_bits as usize - 1 - i;

            let last_non_trivial_block = msb_bit_set / num_bits_in_message as usize;
            // Index to the first block of the remainder that is fully trivial 0
            // and all blocks after it are also trivial zeros
            // This number is in range 1..=num_bocks -1
            let first_trivial_block = last_non_trivial_block + 1;

            // All blocks starting from the first_trivial_block are known to be trivial
            // So we can avoid work.
            // Note that, these are always non-emtpy (i.e there is always at least one non trivial
            // block)
            let mut interesting_remainder1 =
                RadixCiphertext::from(remainder1.blocks[..=last_non_trivial_block].to_vec());
            let mut interesting_remainder2 =
                RadixCiphertext::from(remainder2.blocks[..=last_non_trivial_block].to_vec());
            let mut interesting_divisor =
                RadixCiphertext::from(divisor.blocks[..=last_non_trivial_block].to_vec());
            let mut divisor_ms_blocks = RadixCiphertext::from(
                divisor.blocks[((msb_bit_set + 1) / num_bits_in_message as usize)..].to_vec(),
            );

            // We split the divisor at a block position, when in reality the split should be at a
            // bit position meaning that potentially (depending on msb_bit_set) the
            // split versions share some bits they should not. So we do one PBS on the
            // last block of the interesting_divisor, and first block of divisor_ms_blocks
            // to trim out bits which should not be there

            let mut trim_last_interesting_divisor_bits = || {
                if ((msb_bit_set + 1) % num_bits_in_message as usize) == 0 {
                    return;
                }
                // The last block of the interesting part of the remainder
                // can contain bits which we should not account for
                // we have to zero them out.

                // Where the msb is set in the block
                let pos_in_block = msb_bit_set as u64 % num_bits_in_message;

                // e.g 2 bits in message:
                // if pos_in_block is 0, then we want to keep only first bit (right shift mask
                // by 1) if pos_in_block is 1, then we want to keep the two
                // bits (right shift mask by 0)
                let shift_amount = num_bits_in_message - (pos_in_block + 1);
                // Create mask of 1s on the message part, 0s in the carries
                let full_message_mask = self.key.message_modulus.0 as u64 - 1;
                // Shift the mask so that we will only keep bits we should
                let shifted_mask = full_message_mask >> shift_amount;

                let masking_lut = self.key.generate_lookup_table(|x| x & shifted_mask);
                self.key.apply_lookup_table_assign(
                    interesting_divisor.blocks.last_mut().unwrap(),
                    &masking_lut,
                );
            };

            let mut trim_first_divisor_ms_bits = || {
                if divisor_ms_blocks.blocks.is_empty()
                    || ((msb_bit_set + 1) % num_bits_in_message as usize) == 0
                {
                    return;
                }
                // As above, we need to zero out some bits, but here its in the
                // first block of most significant blocks of the divisor.
                // The block has the same value as the last block of interesting_divisor.
                // Here we will zero out the bits that the trim_last_interesting_divisor_bits
                // above wanted to keep.

                // Where the msb is set in the block
                let pos_in_block = msb_bit_set as u64 % num_bits_in_message;

                // e.g 2 bits in message:
                // if pos_in_block is 0, then we want to discard the first bit (left shift mask
                // by 1) if pos_in_block is 1, then we want to discard the
                // two bits (left shift mask by 2) let shift_amount =
                // num_bits_in_message - pos_in_block as u64;
                let shift_amount = pos_in_block + 1;
                let full_message_mask = self.key.message_modulus.0 as u64 - 1;
                let shifted_mask = full_message_mask << shift_amount;
                // Keep the mask within the range of message bits, so that
                // the estimated degree of the output is < msg_modulus
                let shifted_mask = shifted_mask & full_message_mask;

                let masking_lut = self.key.generate_lookup_table(|x| x & shifted_mask);
                self.key.apply_lookup_table_assign(
                    divisor_ms_blocks.blocks.first_mut().unwrap(),
                    &masking_lut,
                );
            };

            // This does
            //  R := R << 1; R(0) := N(i)
            //
            // We could to that by left shifting, R by one, then unchecked_add the correct numerator
            // bit.
            //
            // However to keep the remainder clean (noise wise), what we do is that we put the
            // remainder block from which we need to extract the bit, as the LSB of the
            // Remainder, so that left shifting will pull the bit we need.
            let mut left_shift_interesting_remainder1 = || {
                let numerator_block = numerator_block_stack
                    .pop()
                    .expect("internal error: empty numerator block stack in div");
                // prepend block and then shift
                interesting_remainder1.blocks.insert(0, numerator_block);
                self.unchecked_scalar_left_shift_assign_parallelized(
                    &mut interesting_remainder1,
                    1,
                );

                // Extract the block we prepended, and see if it should be dropped
                // or added back for processing
                interesting_remainder1.blocks.rotate_left(1);
                // This unwrap is unreachable, as we are removing the block we added earlier
                let numerator_block = interesting_remainder1.blocks.pop().unwrap();
                if pos_in_block != 0 {
                    // We have not yet extracted all the bits from this numerator
                    // so we put it back on the front so that it gets taken next iteration
                    numerator_block_stack.push(numerator_block);
                }
            };

            let mut left_shift_interesting_remainder2 = || {
                self.unchecked_scalar_left_shift_assign_parallelized(
                    &mut interesting_remainder2,
                    1,
                );
            };

            let tasks: [&mut (dyn FnMut() + Send + Sync); 4] = [
                &mut trim_last_interesting_divisor_bits,
                &mut trim_first_divisor_ms_bits,
                &mut left_shift_interesting_remainder1,
                &mut left_shift_interesting_remainder2,
            ];
            tasks.into_par_iter().for_each(|task| task());

            // if interesting_remainder1 != 0 -> interesting_remainder2 == 0
            // if interesting_remainder1 == 0 -> interesting_remainder2 != 0
            // In practice interesting_remainder1 contains the numerator bit,
            // but in that position, interesting_remainder2 always has a 0
            let mut merged_interesting_remainder = interesting_remainder1;
            self.unchecked_add_assign(&mut merged_interesting_remainder, &interesting_remainder2);

            let do_overflowing_sub = || {
                self.unchecked_unsigned_overflowing_sub_parallelized(
                    &merged_interesting_remainder,
                    &interesting_divisor,
                )
            };

            let check_divisor_upper_blocks = || {
                // Do a comparison (==) with 0 for trivial blocks
                let trivial_blocks = &divisor_ms_blocks.blocks;
                if trivial_blocks.is_empty() {
                    self.key.create_trivial(0)
                } else {
                    // We could call unchecked_scalar_ne_parallelized
                    // But we are in the special case where scalar == 0
                    // So we can skip some stuff
                    let tmp = self
                        .compare_blocks_with_zero(trivial_blocks, ZeroComparisonType::Difference);
                    self.is_at_least_one_comparisons_block_true(tmp)
                }
            };

            // Creates a cleaned version (noise wise) of the merged remainder
            // so that it can be safely used in bivariate PBSes
            let create_clean_version_of_merged_remainder = || {
                RadixCiphertext::from_blocks(
                    merged_interesting_remainder
                        .blocks
                        .par_iter()
                        .map(|b| self.key.message_extract(b))
                        .collect(),
                )
            };

            // Use nested join as its easier when we need to return values
            let (
                (mut new_remainder, subtraction_overflowed),
                (at_least_one_upper_block_is_non_zero, mut cleaned_merged_interesting_remainder),
            ) = rayon::join(do_overflowing_sub, || {
                let (r1, r2) = rayon::join(
                    check_divisor_upper_blocks,
                    create_clean_version_of_merged_remainder,
                );

                (r1, r2)
            });
            // explicit drop, so that we do not use it by mistake
            drop(merged_interesting_remainder);

            let overflow_sum = self.key.unchecked_add(
                subtraction_overflowed.as_ref(),
                &at_least_one_upper_block_is_non_zero,
            );
            // Give name to closures to improve readability
            let overflow_happened = |overflow_sum: u64| overflow_sum != 0;
            let overflow_did_not_happen = |overflow_sum: u64| !overflow_happened(overflow_sum);

            // Here, we will do what zero_out_if does, but to stay within noise constraints,
            // we do it by hand so that we apply the factor (shift) to the correct block
            assert!(overflow_sum.degree.get() <= 2); // at_least_one_upper_block_is_non_zero maybe be a trivial 0
            let factor = MessageModulus(overflow_sum.degree.get() + 1);
            let mut conditionally_zero_out_merged_interesting_remainder = || {
                let zero_out_if_overflow_did_not_happen =
                    self.key.generate_lookup_table_bivariate_with_factor(
                        |block, overflow_sum| {
                            if overflow_did_not_happen(overflow_sum) {
                                0
                            } else {
                                block
                            }
                        },
                        factor,
                    );
                cleaned_merged_interesting_remainder
                    .blocks_mut()
                    .par_iter_mut()
                    .for_each(|block| {
                        self.key.unchecked_apply_lookup_table_bivariate_assign(
                            block,
                            &overflow_sum,
                            &zero_out_if_overflow_did_not_happen,
                        );
                    });
            };

            let mut conditionally_zero_out_merged_new_remainder = || {
                let zero_out_if_overflow_happened =
                    self.key.generate_lookup_table_bivariate_with_factor(
                        |block, overflow_sum| {
                            if overflow_happened(overflow_sum) {
                                0
                            } else {
                                block
                            }
                        },
                        factor,
                    );
                new_remainder.blocks_mut().par_iter_mut().for_each(|block| {
                    self.key.unchecked_apply_lookup_table_bivariate_assign(
                        block,
                        &overflow_sum,
                        &zero_out_if_overflow_happened,
                    );
                });
            };

            let mut set_quotient_bit = || {
                let did_not_overflow = self.key.unchecked_apply_lookup_table_bivariate(
                    subtraction_overflowed.as_ref(),
                    &at_least_one_upper_block_is_non_zero,
                    &merge_overflow_flags_luts[pos_in_block],
                );

                self.key
                    .unchecked_add_assign(&mut quotient.blocks[block_of_bit], &did_not_overflow);
            };

            let tasks: [&mut (dyn FnMut() + Send + Sync); 3] = [
                &mut conditionally_zero_out_merged_interesting_remainder,
                &mut conditionally_zero_out_merged_new_remainder,
                &mut set_quotient_bit,
            ];
            tasks.into_par_iter().for_each(|task| task());

            assert_eq!(
                remainder1.blocks[..first_trivial_block].len(),
                cleaned_merged_interesting_remainder.blocks.len()
            );
            assert_eq!(
                remainder2.blocks[..first_trivial_block].len(),
                new_remainder.blocks.len()
            );
            remainder1.blocks[..first_trivial_block]
                .iter_mut()
                .zip(cleaned_merged_interesting_remainder.blocks.iter())
                .for_each(|(remainder_block, new_value)| {
                    remainder_block.clone_from(new_value);
                });
            remainder2.blocks[..first_trivial_block]
                .iter_mut()
                .zip(new_remainder.blocks.iter())
                .for_each(|(remainder_block, new_value)| {
                    remainder_block.clone_from(new_value);
                });
        }

        // Clean the quotient and remainder
        // as even though they have no carries, they are not at nominal noise level
        rayon::join(
            || {
                remainder1
                    .blocks_mut()
                    .par_iter_mut()
                    .zip(remainder2.blocks.par_iter())
                    .for_each(|(r1_block, r2_block)| {
                        self.key.unchecked_add_assign(r1_block, r2_block);
                        self.key.message_extract_assign(r1_block);
                    });
            },
            || {
                quotient.blocks_mut().par_iter_mut().for_each(|block| {
                    self.key.message_extract_assign(block);
                });
            },
        );

        (quotient, remainder1)
    }

    fn signed_unchecked_div_rem_parallelized(
        &self,
        numerator: &SignedRadixCiphertext,
        divisor: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        assert_eq!(
            numerator.blocks.len(),
            divisor.blocks.len(),
            "numerator and divisor must have same length"
        );
        let (positive_numerator, positive_divisor) = rayon::join(
            || {
                let positive_numerator = self.unchecked_abs_parallelized(numerator);
                RadixCiphertext::from_blocks(positive_numerator.into_blocks())
            },
            || {
                let positive_divisor = self.unchecked_abs_parallelized(divisor);
                RadixCiphertext::from_blocks(positive_divisor.into_blocks())
            },
        );

        let ((quotient, remainder), sign_bits_are_different) = rayon::join(
            || self.unsigned_unchecked_div_rem_parallelized(&positive_numerator, &positive_divisor),
            || {
                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;
                let compare_sign_bits = |x, y| {
                    let x_sign_bit = (x >> sign_bit_pos) & 1;
                    let y_sign_bit = (y >> sign_bit_pos) & 1;
                    u64::from(x_sign_bit != y_sign_bit)
                };
                let lut = self.key.generate_lookup_table_bivariate(compare_sign_bits);
                self.key.unchecked_apply_lookup_table_bivariate(
                    numerator.blocks().last().unwrap(),
                    divisor.blocks().last().unwrap(),
                    &lut,
                )
            },
        );

        // Rules are
        // Dividend (numerator) and remainder have the same sign
        // Quotient is negative if signs of numerator and divisor are different
        let (quotient, remainder) = rayon::join(
            || {
                let negated_quotient = self.neg_parallelized(&quotient);

                let quotient = self.unchecked_programmable_if_then_else_parallelized(
                    &sign_bits_are_different,
                    &negated_quotient,
                    &quotient,
                    |x| x == 1,
                    true,
                );
                SignedRadixCiphertext::from_blocks(quotient.into_blocks())
            },
            || {
                let negated_remainder = self.neg_parallelized(&remainder);

                let sign_block = numerator.blocks().last().unwrap();
                let sign_bit_pos = self.key.message_modulus.0.ilog2() - 1;

                let remainder = self.unchecked_programmable_if_then_else_parallelized(
                    sign_block,
                    &negated_remainder,
                    &remainder,
                    |sign_block| (sign_block >> sign_bit_pos) == 1,
                    true,
                );
                SignedRadixCiphertext::from_blocks(remainder.into_blocks())
            },
        );

        (quotient, remainder)
    }

    /// Computes homomorphically the quotient and remainder of the division between two ciphertexts
    ///
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
    /// let msg1 = 97;
    /// let msg2 = 14;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let (q_res, r_res) = sks.div_rem_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let q: u64 = cks.decrypt(&q_res);
    /// let r: u64 = cks.decrypt(&r_res);
    /// assert_eq!(q, msg1 / msg2);
    /// assert_eq!(r, msg1 % msg2);
    /// ```
    pub fn div_rem_parallelized<T>(&self, numerator: &T, divisor: &T) -> (T, T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_numerator;
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.clone();
                self.full_propagate_parallelized(&mut tmp_divisor);
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                tmp_numerator = numerator.clone();
                self.full_propagate_parallelized(&mut tmp_numerator);
                (&tmp_numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.clone();
                tmp_numerator = numerator.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_numerator),
                    || self.full_propagate_parallelized(&mut tmp_divisor),
                );
                (&tmp_numerator, &tmp_divisor)
            }
        };

        self.unchecked_div_rem_parallelized(numerator, divisor)
    }

    pub fn smart_div_rem_parallelized<T>(&self, numerator: &mut T, divisor: &mut T) -> (T, T)
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !numerator.block_carries_are_empty() {
                    self.full_propagate_parallelized(numerator);
                }
            },
            || {
                if !divisor.block_carries_are_empty() {
                    self.full_propagate_parallelized(divisor);
                }
            },
        );
        self.unchecked_div_rem_parallelized(numerator, divisor)
    }

    //======================================================================
    //                Div
    //======================================================================

    pub fn unchecked_div_assign_parallelized<T>(&self, numerator: &mut T, divisor: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let (q, _r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = q;
    }

    pub fn unchecked_div_parallelized<T>(&self, numerator: &T, divisor: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (q, _r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        q
    }

    pub fn smart_div_assign_parallelized<T>(&self, numerator: &mut T, divisor: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        let (q, _r) = self.smart_div_rem_parallelized(numerator, divisor);
        *numerator = q;
    }

    pub fn smart_div_parallelized<T>(&self, numerator: &mut T, divisor: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (q, _r) = self.smart_div_rem_parallelized(numerator, divisor);
        q
    }

    pub fn div_assign_parallelized<T>(&self, numerator: &mut T, divisor: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.clone();
                self.full_propagate_parallelized(&mut tmp_divisor);
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                self.full_propagate_parallelized(numerator);
                (numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.clone();
                rayon::join(
                    || self.full_propagate_parallelized(numerator),
                    || self.full_propagate_parallelized(&mut tmp_divisor),
                );
                (numerator, &tmp_divisor)
            }
        };

        let (q, _r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = q;
    }

    /// Computes homomorphically the quotient of the division between two ciphertexts
    ///
    /// # Note
    ///
    /// If you need both the quotien and remainder use [Self::div_rem_parallelized].
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
    /// let msg1 = 97;
    /// let msg2 = 14;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.div_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 / msg2);
    /// ```
    pub fn div_parallelized<T>(&self, numerator: &T, divisor: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (q, _r) = self.div_rem_parallelized(numerator, divisor);
        q
    }

    //======================================================================
    //                Rem
    //======================================================================

    pub fn unchecked_rem_assign_parallelized<T>(&self, numerator: &mut T, divisor: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let (_q, r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = r;
    }

    pub fn unchecked_rem_parallelized<T>(&self, numerator: &T, divisor: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (_q, r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        r
    }

    pub fn smart_rem_assign_parallelized<T>(&self, numerator: &mut T, divisor: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        let (_q, r) = self.smart_div_rem_parallelized(numerator, divisor);
        *numerator = r;
    }

    pub fn smart_rem_parallelized<T>(&self, numerator: &mut T, divisor: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (_q, r) = self.smart_div_rem_parallelized(numerator, divisor);
        r
    }

    pub fn rem_assign_parallelized<T>(&self, numerator: &mut T, divisor: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_divisor;

        let (numerator, divisor) = match (
            numerator.block_carries_are_empty(),
            divisor.block_carries_are_empty(),
        ) {
            (true, true) => (numerator, divisor),
            (true, false) => {
                tmp_divisor = divisor.clone();
                self.full_propagate_parallelized(&mut tmp_divisor);
                (numerator, &tmp_divisor)
            }
            (false, true) => {
                self.full_propagate_parallelized(numerator);
                (numerator, divisor)
            }
            (false, false) => {
                tmp_divisor = divisor.clone();
                rayon::join(
                    || self.full_propagate_parallelized(numerator),
                    || self.full_propagate_parallelized(&mut tmp_divisor),
                );
                (numerator, &tmp_divisor)
            }
        };

        let (_q, r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = r;
    }

    /// Computes homomorphically the remainder (rest) of the division between two ciphertexts
    ///
    /// # Note
    ///
    /// If you need both the quotien and remainder use [Self::div_rem_parallelized].
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
    /// let msg1 = 97;
    /// let msg2 = 14;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.rem_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 % msg2);
    /// ```
    pub fn rem_parallelized<T>(&self, numerator: &T, divisor: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let (_q, r) = self.div_rem_parallelized(numerator, divisor);
        r
    }
}
