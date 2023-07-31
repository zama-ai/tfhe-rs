use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::comparator::ZeroComparisonType;
use crate::integer::ServerKey;

use super::bit_extractor::BitExtractor;

impl ServerKey {
    //======================================================================
    //                Div Rem
    //======================================================================
    pub fn unchecked_div_rem_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        // Pseudo-code of the school-bool / long-division algorithm:
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
        let num_blocks = numerator.blocks.len();
        let num_bits_in_block = self.key.message_modulus.0.ilog2() as u64;
        let total_bits = num_bits_in_block * num_blocks as u64;

        let mut quotient = self.create_trivial_zero_radix(num_blocks);
        let mut remainder = self.create_trivial_zero_radix(num_blocks);

        let merge_two_cmp_lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x == 1 && y == 1));

        let bit_extractor = BitExtractor::new(self, num_bits_in_block as usize);
        let numerator_bits = bit_extractor.extract_all_bits(&numerator.blocks);

        for i in (0..=total_bits as usize - 1).rev() {
            let block_of_bit = i / num_bits_in_block as usize;
            let pos_in_block = i % num_bits_in_block as usize;

            // i goes from (total_bits - 1 to 0)
            // msb_bit_set goes from 0 to total_bits - 1
            let msb_bit_set = total_bits as usize - 1 - i;
            let first_trivial_block = (msb_bit_set / num_bits_in_block as usize) + 1;

            // All blocks starting from the first_trivial_block are known to be trivial
            // So we can avoid work.
            // Note that, these are always non-emtpy
            let mut interesting_remainder =
                RadixCiphertext::from(remainder.blocks[..first_trivial_block].to_vec());
            let mut interesting_divisor =
                RadixCiphertext::from(divisor.blocks[..first_trivial_block].to_vec());

            self.unchecked_scalar_left_shift_assign_parallelized(&mut interesting_remainder, 1);
            self.key
                .unchecked_add_assign(&mut interesting_remainder.blocks[0], &numerator_bits[i]);

            // For comparisons, trivial are dealt with differently
            let (non_trivial_blocks_are_ge, trivial_blocks_are_zero) = rayon::join(
                || {
                    // Do a true >= comparison for non trivial blocks
                    self.unchecked_ge_parallelized(&interesting_remainder, &interesting_divisor)
                },
                || {
                    // Do a comparison (==) with 0 for trivial blocks
                    let trivial_blocks = &divisor.blocks[first_trivial_block..];
                    if trivial_blocks.is_empty() {
                        self.key.create_trivial(1)
                    } else {
                        let tmp = self
                            .compare_blocks_with_zero(trivial_blocks, ZeroComparisonType::Equality);
                        self.are_all_comparisons_block_true(tmp)
                    }
                },
            );

            // We need to 'merge' the two comparisons results
            // from being in two blocks into one,
            // to be able to use that merged block as a 'control' block
            // to zero out (or not) 'interesting_divisor'.
            //
            // If parameters have enough message space,
            // the merge can be done using an addition,
            // otherwise we have to use a bivariate PBS.
            //
            // This has an impact as merging using addition means
            // the merge result is in [0, 1, 2], while merging
            // using bivariate PBS gives a result in [0, 1].
            //
            // is_remainder_greater_or_eq_than_divisor will be Some(block)
            // where block encrypts a boolean value
            // if the merge is done with PBS, None otherwise.
            //
            // Towards the end of the loop, we need
            // is_remainder_greater_or_eq_than_divisor to actually be Some(block),
            // the PBS merge will then happen at this point.
            // Delaying this PBS merge, is done because it creates noticeable
            // performance improvement.
            // When the PBS is done later (rather than right now), it will
            // be done in parrallel with another PBS based operation meaning the
            // latency of this function won't be impacted (compared to doing it right now).
            let mut is_remainder_greater_or_eq_than_divisor;
            if self.key.message_modulus.0 < 3 {
                let merged_cmp = self.key.unchecked_apply_lookup_table_bivariate(
                    &trivial_blocks_are_zero,
                    &non_trivial_blocks_are_ge.blocks[0],
                    &merge_two_cmp_lut,
                );

                self.zero_out_if_condition_is_false(&mut interesting_divisor, &merged_cmp);
                is_remainder_greater_or_eq_than_divisor = Some(merged_cmp)
            } else {
                let summed_cmp = self.key.unchecked_add(
                    &trivial_blocks_are_zero,
                    &non_trivial_blocks_are_ge.blocks[0],
                );
                self.zero_out_if(&mut interesting_divisor, &summed_cmp, |summed_cmp| {
                    summed_cmp != 2 // summed_cmp != 2 => remainder < divisor
                });
                is_remainder_greater_or_eq_than_divisor = None;
            }

            rayon::join(
                || {
                    self.sub_assign_parallelized(&mut interesting_remainder, &interesting_divisor);
                    // Copy back into the real remainder
                    remainder.blocks[..first_trivial_block]
                        .iter_mut()
                        .zip(interesting_remainder.blocks.iter())
                        .for_each(|(remainder_block, new_value)| {
                            remainder_block.clone_from(new_value);
                        });
                },
                || {
                    // This is the place where we merge the two cmp blocks
                    // if it was not done earlier.
                    let merged_cmp =
                        is_remainder_greater_or_eq_than_divisor.get_or_insert_with(|| {
                            self.key.unchecked_apply_lookup_table_bivariate(
                                &trivial_blocks_are_zero,
                                &non_trivial_blocks_are_ge.blocks[0],
                                &merge_two_cmp_lut,
                            )
                        });
                    self.key
                        .unchecked_scalar_left_shift_assign(merged_cmp, pos_in_block as u8);
                    self.key
                        .unchecked_add_assign(&mut quotient.blocks[block_of_bit], merged_cmp);
                },
            );
        }

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
    pub fn div_rem_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let mut tmp_numerator: RadixCiphertext;
        let mut tmp_divisor: RadixCiphertext;

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

    pub fn smart_div_rem_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &mut RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        rayon::join(
            || {
                if !numerator.block_carries_are_empty() {
                    self.full_propagate_parallelized(numerator)
                }
            },
            || {
                if !divisor.block_carries_are_empty() {
                    self.full_propagate_parallelized(divisor)
                }
            },
        );
        self.unchecked_div_rem_parallelized(numerator, divisor)
    }

    //======================================================================
    //                Div
    //======================================================================

    pub fn unchecked_div_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &RadixCiphertext,
    ) {
        let (q, _r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = q;
    }

    pub fn unchecked_div_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> RadixCiphertext {
        let (q, _r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        q
    }

    pub fn smart_div_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &mut RadixCiphertext,
    ) {
        let (q, _r) = self.smart_div_rem_parallelized(numerator, divisor);
        *numerator = q;
    }

    pub fn smart_div_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        let (q, _r) = self.smart_div_rem_parallelized(numerator, divisor);
        q
    }

    pub fn div_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &RadixCiphertext,
    ) {
        let mut tmp_divisor: RadixCiphertext;

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
    pub fn div_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> RadixCiphertext {
        let (q, _r) = self.div_rem_parallelized(numerator, divisor);
        q
    }

    //======================================================================
    //                Rem
    //======================================================================

    pub fn unchecked_rem_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &RadixCiphertext,
    ) {
        let (_q, r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        *numerator = r;
    }

    pub fn unchecked_rem_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> RadixCiphertext {
        let (_q, r) = self.unchecked_div_rem_parallelized(numerator, divisor);
        r
    }

    pub fn smart_rem_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &mut RadixCiphertext,
    ) {
        let (_q, r) = self.smart_div_rem_parallelized(numerator, divisor);
        *numerator = r;
    }

    pub fn smart_rem_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        let (_q, r) = self.smart_div_rem_parallelized(numerator, divisor);
        r
    }

    pub fn rem_assign_parallelized(
        &self,
        numerator: &mut RadixCiphertext,
        divisor: &RadixCiphertext,
    ) {
        let mut tmp_divisor: RadixCiphertext;

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
    pub fn rem_parallelized(
        &self,
        numerator: &RadixCiphertext,
        divisor: &RadixCiphertext,
    ) -> RadixCiphertext {
        let (_q, r) = self.div_rem_parallelized(numerator, divisor);
        r
    }
}
