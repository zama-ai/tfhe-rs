use super::ServerKey;
use crate::core_crypto::prelude::UnsignedInteger;
use crate::integer::ciphertext::boolean_value::BooleanBlock;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::{Ciphertext, MessageModulus};
use rayon::prelude::*;

#[derive(Debug, Copy, Clone)]
enum ComparisonKind {
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

/// Given the last block of 2 _signed_ numbers x and y, and a borrow (0 or 1)
///
/// Requires MessageModulus > 2
///
/// returns whether x < y
fn is_x_less_than_y_given_input_borrow(
    last_x_block: u64,
    last_y_block: u64,
    borrow: u64,
    message_modulus: MessageModulus,
) -> u64 {
    assert!(message_modulus.0 > 2, "This requires MessageModulus > 2");
    let last_bit_pos = message_modulus.0.ilog2() - 1;

    let mask = (1 << last_bit_pos) - 1;
    let x_without_last_bit = last_x_block & mask;
    let y_without_last_bit = last_y_block & mask;

    let input_borrow_to_last_bit = x_without_last_bit < (y_without_last_bit + borrow);

    let result = last_x_block.wrapping_sub(last_y_block + borrow);

    let output_sign_bit = (result >> last_bit_pos) & 1;
    let output_borrow = last_x_block < (last_y_block + borrow);

    let overflow_flag = input_borrow_to_last_bit ^ output_borrow;

    output_sign_bit ^ u64::from(overflow_flag)
}

impl ServerKey {
    pub fn unchecked_eq_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x == y));
        let mut block_comparisons = lhs.blocks().to_vec();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let is_equal_result = self.are_all_comparisons_block_true(block_comparisons);

        BooleanBlock::new_unchecked(is_equal_result)
    }

    pub fn unchecked_ne_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        // one for all the threads as opposed to one per thread
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x != y));
        let mut block_comparisons = lhs.blocks().to_vec();
        block_comparisons
            .par_iter_mut()
            .zip(rhs.blocks().par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let mut block_comparisons_2 = Vec::with_capacity(block_comparisons.len() / 2);
        let is_non_zero = self.key.generate_lookup_table(|x| u64::from(x != 0));

        while block_comparisons.len() > 1 {
            block_comparisons
                .par_chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }
                    self.key.apply_lookup_table(&sum, &is_non_zero)
                })
                .collect_into_vec(&mut block_comparisons_2);
            std::mem::swap(&mut block_comparisons_2, &mut block_comparisons);
        }

        BooleanBlock::new_unchecked(
            block_comparisons
                .into_iter()
                .next()
                .unwrap_or_else(|| self.key.create_trivial(0)),
        )
    }

    /// This implements all comparisons (<, <=, >, >=) for both signed and unsigned
    ///
    /// * inputs must have the same number of blocks
    /// * block carries of both inputs must be empty
    /// * carry modulus == message modulus
    fn compare<T>(&self, a: &T, b: &T, compare: ComparisonKind) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        assert_eq!(
            a.blocks().len(),
            b.blocks().len(),
            "lhs and rhs must have the same number of blocks"
        );

        assert!(a.block_carries_are_empty(), "Block carries must be empty");
        assert!(b.block_carries_are_empty(), "Block carries must be empty");
        assert_eq!(
            self.carry_modulus().0,
            self.message_modulus().0,
            "The carry modulus must be == to the message modulus"
        );

        if a.blocks().is_empty() {
            // We interpret empty as 0
            return match compare {
                ComparisonKind::Less | ComparisonKind::Greater => {
                    self.create_trivial_boolean_block(false)
                }
                ComparisonKind::LessOrEqual | ComparisonKind::GreaterOrEqual => {
                    self.create_trivial_boolean_block(true)
                }
            };
        }

        // We have that `a < b` <=> `does_sub_overflows(a, b)` and we know how to do this.
        // Now, to have other comparisons, we will re-express them as less than (`<`)
        // with some potential boolean negation
        //
        // Note that for signed ciphertext it's not the overflowing sub that is used,
        // but it's still something that is based on the subtraction
        //
        // For both signed and unsigned, a subtraction with borrow is used
        // (as opposed to adding the negation)
        let (lhs, rhs, invert_subtraction_result) = match compare {
            // The easiest case, nothing changes
            ComparisonKind::Less => (a, b, false),
            //     `a <= b`
            // <=> `not(b < a)`
            // <=> `not(does_sub_overflows(b, a))`
            ComparisonKind::LessOrEqual => (b, a, true),
            //     `a > b`
            // <=> `b < a`
            // <=> `does_sub_overflows(b, a)`
            ComparisonKind::Greater => (b, a, false),
            //     `a >= b`
            // <=> `b <= a`
            // <=> `not(a < b)`
            // <=> `not(does_sub_overflows(a, b))`
            ComparisonKind::GreaterOrEqual => (a, b, true),
        };

        // When there is only one block in both operands,
        // we can take a shortcut by using bivariate PBS.
        if a.blocks().len() == 1 {
            let lut = if T::IS_SIGNED {
                self.key.generate_lookup_table_bivariate(|x, y| {
                    u64::from(invert_subtraction_result)
                        ^ is_x_less_than_y_given_input_borrow(x, y, 0, self.message_modulus())
                })
            } else {
                self.key.generate_lookup_table_bivariate(|x, y| {
                    let overflowed = x < y;
                    u64::from(invert_subtraction_result ^ overflowed)
                })
            };
            let result = self.key.unchecked_apply_lookup_table_bivariate(
                &lhs.blocks()[0],
                &rhs.blocks()[0],
                &lut,
            );
            return BooleanBlock::new_unchecked(result);
        }

        let sub_blocks = lhs
            .blocks()
            .iter()
            .zip(rhs.blocks().iter())
            .map(|(lhs_b, rhs_b)| self.key.unchecked_sub(lhs_b, rhs_b))
            .collect::<Vec<_>>();

        let block_modulus = self.message_modulus().0 * self.carry_modulus().0;
        let num_bits_in_block = block_modulus.ilog2();
        let grouping_size = num_bits_in_block as usize;

        // We are going to group blocks and compute how each group propagates/generates a borrow
        //
        // Again, in unsigned representation the output borrow of the whole operation (i.e. the
        // borrow generated by the last group) tells us the result of the comparison. For signed
        // representation we need to XOR the overflow flag and the sign bit of the result.
        let block_states = {
            let message_modulus = self.message_modulus().0 as u64;

            let mut first_grouping_luts = vec![{
                let first_block_state_fn = |block| {
                    if block < message_modulus {
                        1 // Borrows
                    } else {
                        0 // Nothing
                    }
                };
                self.key.generate_lookup_table(first_block_state_fn)
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
                first_grouping_luts.push(self.key.generate_lookup_table(state_fn));
            }

            let other_block_state_luts = (0..grouping_size)
                .map(|i| {
                    let state_fn = |block| {
                        #[allow(clippy::comparison_chain)]
                        let r = if block < message_modulus {
                            2 // Generates borrow
                        } else if block == message_modulus {
                            1 // Propagates a borrow
                        } else {
                            0 // Does not borrow
                        };

                        r << i
                    };
                    self.key.generate_lookup_table(state_fn)
                })
                .collect::<Vec<_>>();

            let block_states =
                // With unsigned ciphertexts as, overflow (i.e. does the last block needs to borrow)
                // directly translates to lhs < rhs we compute the blocks states for all the blocks
                //
                // For signed numbers, we need to do something more specific with the last block
                // thus, we don't compute the last block state
                sub_blocks[..sub_blocks.len() - usize::from(T::IS_SIGNED)]
                    .par_iter()
                    .enumerate()
                    .map(|(index, block)| {
                        let grouping_index = index / grouping_size;
                        let is_in_first_grouping = grouping_index == 0;
                        let index_in_grouping = index % (grouping_size);

                        let luts = if is_in_first_grouping {
                            &first_grouping_luts[index_in_grouping]
                        } else {
                            &other_block_state_luts[index_in_grouping]
                        };

                        self.key.apply_lookup_table(block, luts)
                    })
                    .collect::<Vec<_>>();

            block_states
        };

        // group borrows and simulator of last block
        let (
            (mut group_borrows, use_sequential_algorithm_to_resolved_grouping_carries),
            maybe_prepared_signed_check,
        ) = rayon::join(
            || {
                self.compute_group_borrow_state(
                    // May only invert if T is not signed
                    // As when there is only one group, in the unsigned case since overflow
                    // directly translate to lhs < rhs, we can ask the LUT used to do the
                    // inversion for us.
                    //
                    // In signed case as it's a bit more complex, we never want to
                    !T::IS_SIGNED && invert_subtraction_result,
                    grouping_size,
                    block_states,
                )
            },
            || {
                // When the ciphertexts are signed, finding whether lhs < rhs by doing a sub
                // is less direct than in unsigned where we can check for overflow.
                if T::IS_SIGNED && self.message_modulus().0 > 2 {
                    // Luckily, when the blocks have 4 bits, we can precompute and store in a block
                    // the 2 possible values for `lhs < rhs` depending on whether the last block
                    // will be borrowed from.
                    let lut = self.key.generate_lookup_table_bivariate(|x, y| {
                        let b0 =
                            is_x_less_than_y_given_input_borrow(x, y, 0, self.message_modulus());
                        let b1 =
                            is_x_less_than_y_given_input_borrow(x, y, 1, self.message_modulus());
                        (b1 << 1 | b0) << 2
                    });

                    Some(self.key.apply_lookup_table_bivariate(
                        lhs.blocks().last().unwrap(),
                        rhs.blocks().last().unwrap(),
                        &lut,
                    ))
                } else if T::IS_SIGNED {
                    // When we have just 2 bits (message and carry included)
                    // we will have to do more work.
                    // This step is preparing a block that will be used to compute the output borrow
                    // of the whole subtraction
                    let message_modulus = self.message_modulus().0 as u64;
                    let lut = self.key.generate_lookup_table_bivariate(|x, y| {
                        let value = x.wrapping_sub(y).wrapping_add(message_modulus);

                        #[allow(clippy::comparison_chain)]
                        if value < message_modulus {
                            2 << 1
                        } else if value == message_modulus {
                            1 << 1
                        } else {
                            0
                        }
                    });

                    Some(self.key.apply_lookup_table_bivariate(
                        lhs.blocks().last().unwrap(),
                        rhs.blocks().last().unwrap(),
                        &lut,
                    ))
                } else {
                    None
                }
            },
        );

        // This blocks contains part of the information necessary to conclude, it just needs
        // some input borrow
        // There are 3 possibilities:
        //
        // * If the ciphertext is unsigned, it contains the information that will allow determining
        //   the output borrow
        // * If the ciphertext is signed and a block can encrypt at least 4 bits (carry + msg) then
        //   the block contains information that will allow determining the result of x < y in one
        //   PBS
        // * If the ciphertext is signed and a block can encrypt 2 bits (msg + carry) then the block
        //   contains information that will allow computing the output borrow, which will then be
        //   used to get the overflow flag then the final result
        let mut result_block = group_borrows.pop().unwrap();
        if let Some(block) = maybe_prepared_signed_check {
            self.key.unchecked_add_assign(&mut result_block, &block);
        }

        // Third step: resolving borrow propagation between the groups
        let resolved_borrows = if group_borrows.is_empty() {
            // There was only one group, and the borrow generated by this group
            // has already been added to the `overflow_block`, just earlier
            if T::IS_SIGNED {
                // There is still one step to determine the result of the comparison
                // being done further down.
                // It will require an input borrow for the last group
                // which is 0 here because there was only one group thus,
                // the last group is the same as the first group,
                // and the input borrow of the first group is 0
                vec![self.key.create_trivial(0)]
            } else {
                // When unsigned, the result is already known at this point
                return BooleanBlock::new_unchecked(result_block);
            }
        } else if use_sequential_algorithm_to_resolved_grouping_carries {
            self.resolve_carries_of_groups_sequentially(group_borrows, grouping_size)
        } else {
            self.resolve_carries_of_groups_using_hillis_steele(group_borrows)
        };

        if T::IS_SIGNED && self.message_modulus().0 > 2 {
            // For signed numbers its less direct to do lhs < rhs using subtraction
            // fortunately when we have at least 4 bits we can encode all the needed information
            // in one block and conclude in 1 PBS
            self.key
                .unchecked_add_assign(&mut result_block, resolved_borrows.last().unwrap());
            let lut = self.key.generate_lookup_table(|block| {
                // If `resolved_borrows.len() == 1`, then group_borrows was empty,
                // This means 2 things:
                // * The overflow block already contains the borrow
                // * But the position of the borrow is one less bit further
                let index = if resolved_borrows.len() == 1 { 0 } else { 1 };
                let input_borrow = (block >> index) & 1;

                // Here, depending on the input borrow, we retrieve
                // the bit that tells us if lhs < rhs
                let r = if input_borrow == 1 {
                    (block >> 3) & 1
                } else {
                    (block >> 2) & 1
                };
                u64::from(invert_subtraction_result) ^ r
            });

            self.key.apply_lookup_table_assign(&mut result_block, &lut);

            BooleanBlock::new_unchecked(result_block)
        } else if T::IS_SIGNED {
            // Here, message_modulus == 2 (1 bit of message), 2 bits in a block
            // Se we don't have enough bits to store all the needed stuff, thus
            // we have to do a few more PBS to get the result of lhs < rhs

            let input_borrow = resolved_borrows.last().unwrap();
            let (mut shifted_output_borrow, mut new_sign_bit) = rayon::join(
                || {
                    self.key
                        .unchecked_add_assign(&mut result_block, input_borrow);
                    if resolved_borrows.len() == 1 {
                        // There was one group, so the input borrow is not properly positioned
                        // for the next steps to work, so we add the clear value 1, this will
                        // push the borrow bit if there was one
                        self.key.unchecked_scalar_add_assign(&mut result_block, 1);
                    }

                    // This exploits the fact that the padding of the input bit will be set if
                    // a borrow is generated, the lut always returns -1:
                    // If the padding bit is set: it will return -(-1) = 1
                    // If it's not set: it will return -1
                    //
                    // We then add 1, so the possible values are:
                    // * 2 if a borrow was generated
                    // * 0 otherwise
                    //
                    // We use the fact that the borrow bit is at index 1 a bit later
                    let lut = self.key.generate_lookup_table(|_| {
                        // return -1 coded on 3 bits (1 message, 1 carry, 1 padding)
                        0b111
                    });
                    let mut shifted_output_borrow =
                        self.key.apply_lookup_table(&result_block, &lut);
                    self.key
                        .unchecked_scalar_add_assign(&mut shifted_output_borrow, 1);
                    shifted_output_borrow
                },
                || {
                    let mut sub_of_last_blocks = sub_blocks.last().cloned().unwrap();
                    crate::core_crypto::prelude::lwe_ciphertext_sub_assign(
                        &mut sub_of_last_blocks.ct,
                        &input_borrow.ct,
                    );
                    // Degree does not change as we do a subtraction, so worst case we subtract 0
                    // which does not change the degree
                    sub_of_last_blocks
                        .set_noise_level(sub_of_last_blocks.noise_level + input_borrow.noise_level);
                    self.key.message_extract_assign(&mut sub_of_last_blocks);
                    sub_of_last_blocks
                },
            );

            let overflow_flag_lut = self.key.generate_lookup_table(|x| {
                let output_borrow = (x >> 1) & 1;
                let input_borrow = x & 1;

                input_borrow ^ output_borrow
            });
            self.key
                .unchecked_add_assign(&mut shifted_output_borrow, input_borrow);
            self.key
                .apply_lookup_table_assign(&mut shifted_output_borrow, &overflow_flag_lut);
            let overflow_flag = shifted_output_borrow; // Rename

            // Since blocks have one bit of message, the new last block is also the new sign bit
            let lut = self
                .key
                .generate_lookup_table_bivariate(|new_sign_bit, overflow_flag| {
                    u64::from(invert_subtraction_result) ^ (new_sign_bit ^ overflow_flag)
                });

            assert!(new_sign_bit.noise_level <= NoiseLevel::NOMINAL);
            assert!(overflow_flag.noise_level <= NoiseLevel::NOMINAL);
            self.key.unchecked_apply_lookup_table_bivariate_assign(
                &mut new_sign_bit,
                &overflow_flag,
                &lut,
            );

            BooleanBlock::new_unchecked(new_sign_bit)
        } else {
            // For unsigned numbers, if the last block borrows, then the subtraction
            // overflowed, which directly means lhs < rhs
            self.key
                .unchecked_add_assign(&mut result_block, resolved_borrows.last().unwrap());
            let lut = self.key.generate_lookup_table(|block| {
                let overflowed = (block >> 1) & 1;
                u64::from(invert_subtraction_result) ^ overflowed
            });

            self.key.apply_lookup_table_assign(&mut result_block, &lut);

            BooleanBlock::new_unchecked(result_block)
        }
    }

    /// The invert_result boolean is only used when there is one and only one group
    fn compute_group_borrow_state(
        &self,
        invert_result: bool,
        grouping_size: usize,
        block_states: Vec<Ciphertext>,
    ) -> (Vec<Ciphertext>, bool) {
        if block_states.len() == 1 {
            return (block_states, true);
        }

        let message_modulus = self.key.message_modulus.0 as u64;
        let block_modulus = message_modulus * self.carry_modulus().0 as u64;
        let num_bits_in_block = block_modulus.ilog2();
        let num_blocks = block_states.len();
        let num_groups = num_blocks.div_ceil(grouping_size);

        let num_groupings = num_blocks.div_ceil(grouping_size);
        let num_carry_to_resolve = num_groupings - 1;

        let sequential_depth = (num_carry_to_resolve as u32) / (grouping_size as u32 - 1);

        let hillis_steel_depth = if num_carry_to_resolve == 0 {
            0
        } else {
            num_carry_to_resolve.ceil_ilog2()
        };

        let use_sequential_algorithm_to_resolved_grouping_carries = if num_bits_in_block >= 4 {
            sequential_depth <= hillis_steel_depth
        } else {
            true // Hillis-Steele base propagation requires 4 bits
        };

        // This will be used only if there are at least 2 groups
        let first_group_propagation_lut = self
            .key
            .generate_lookup_table(|block| (block >> (num_bits_in_block as u64 - 1)) & 1);

        // This stores the LUTs that output the propagation result of the other groupings
        let grouping_chunk_pgn_luts = if use_sequential_algorithm_to_resolved_grouping_carries {
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
                        if block == (block_modulus - 1) {
                            0
                        } else {
                            // u64::MAX is -1 in two's complement
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
                if block == (block_modulus - 1) {
                    // All bits set to 1 (e.g. 0b1111), means propagate
                    2
                } else {
                    // u64::MAX is -1 in tow's complement
                    // We apply the modulus including the padding bit
                    u64::MAX % (1 << (block_modulus + 1))
                }
            })]
        };

        // The last group may not be full
        let mut num_blocks_in_last_group = block_states.len() % grouping_size;
        if num_blocks_in_last_group == 0 {
            num_blocks_in_last_group = grouping_size;
        }
        let (last_group_lut, last_group_lut_corrector) = if num_groups == 1 {
            // The last group is the only one
            let lut = self.key.generate_lookup_table(|cum_sum_block| {
                let index_of_last_block = num_blocks_in_last_group - 1;
                let overflowed = (cum_sum_block >> index_of_last_block) & 1;
                u64::from(invert_result) ^ overflowed
            });
            (lut, 0)
        } else {
            let may_have_its_padding_bit_set = num_blocks_in_last_group == grouping_size;
            if may_have_its_padding_bit_set {
                let lut = self.key.generate_lookup_table(|cum_sum_block| {
                    if cum_sum_block == (block_modulus - 1) {
                        0
                    } else {
                        // u64::MAX is -1 in tow's complement
                        // We apply the modulus including the padding bit
                        u64::MAX % (1 << (num_bits_in_block + 1))
                    }
                });
                (lut, 1)
            } else {
                let lut = self.key.generate_lookup_table(|cum_sum_block| {
                    let propagate_state = (1 << num_blocks_in_last_group) - 1;
                    #[allow(clippy::comparison_chain)]
                    if cum_sum_block > propagate_state {
                        2 // Generates
                    } else if cum_sum_block == propagate_state {
                        1 // Propagate
                    } else {
                        0
                    }
                });
                (lut, 0)
            }
        };

        // Stores for each group, the cum sum the block state of each of its member
        let group_propagation_state = block_states
            .par_chunks(grouping_size)
            .enumerate()
            .map(|(i, grouping)| {
                let mut result = grouping[0].clone();
                for other in &grouping[1..] {
                    self.key.unchecked_add_assign(&mut result, other);
                }

                // i == (num_groups - 1) takes precedence over
                // i == 0 as when num_groups -1 == 0, the correct lut to use is
                // the last group lut
                if i == num_groups - 1 {
                    self.key
                        .apply_lookup_table_assign(&mut result, &last_group_lut);
                    self.key
                        .unchecked_scalar_add_assign(&mut result, last_group_lut_corrector)
                } else if i == 0 {
                    self.key
                        .apply_lookup_table_assign(&mut result, &first_group_propagation_lut)
                } else {
                    let index = if use_sequential_algorithm_to_resolved_grouping_carries {
                        // Select the correct LUT so that the result
                        // is aligned to the correct position for sequential algorithm
                        // to work
                        (i - 1) % (grouping_size - 1)
                    } else {
                        0
                    };
                    self.key
                        .apply_lookup_table_assign(&mut result, &grouping_chunk_pgn_luts[index]);

                    let corrector = if use_sequential_algorithm_to_resolved_grouping_carries {
                        1 << ((i - 1) % (grouping_size - 1))
                    } else {
                        1
                    };
                    self.key.unchecked_scalar_add_assign(&mut result, corrector);
                    result.degree = crate::shortint::ciphertext::Degree::new(3);
                };

                result
            })
            .collect::<Vec<_>>();

        (
            group_propagation_state,
            use_sequential_algorithm_to_resolved_grouping_carries,
        )
    }

    pub fn unchecked_gt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.compare(lhs, rhs, ComparisonKind::Greater)
    }

    pub fn unchecked_ge_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.compare(lhs, rhs, ComparisonKind::GreaterOrEqual)
    }

    pub fn unchecked_lt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.compare(lhs, rhs, ComparisonKind::Less)
    }

    pub fn unchecked_le_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        self.compare(lhs, rhs, ComparisonKind::LessOrEqual)
    }

    pub fn unchecked_max_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let is_superior = self.unchecked_gt_parallelized(lhs, rhs);
        self.unchecked_if_then_else_parallelized(&is_superior, lhs, rhs)
    }

    pub fn unchecked_min_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let is_inferior = self.unchecked_lt_parallelized(lhs, rhs);
        self.unchecked_if_then_else_parallelized(&is_inferior, lhs, rhs)
    }

    pub fn smart_eq_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn smart_ne_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !lhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(lhs);
                }
            },
            || {
                if !rhs.block_carries_are_empty() {
                    self.full_propagate_parallelized(rhs);
                }
            },
        );
        self.unchecked_ne_parallelized(lhs, rhs)
    }

    pub fn smart_gt_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn smart_ge_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn smart_lt_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn smart_le_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_le_parallelized(lhs, rhs)
    }

    pub fn smart_max_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_max_parallelized(lhs, rhs)
    }

    pub fn smart_min_parallelized<T>(&self, lhs: &mut T, rhs: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate_parallelized(rhs);
        }
        self.unchecked_min_parallelized(lhs, rhs)
    }

    pub fn eq_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_eq_parallelized(lhs, rhs)
    }

    pub fn ne_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ne_parallelized(lhs, rhs)
    }

    pub fn gt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_gt_parallelized(lhs, rhs)
    }

    pub fn ge_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_ge_parallelized(lhs, rhs)
    }

    pub fn lt_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_lt_parallelized(lhs, rhs)
    }

    pub fn le_parallelized<T>(&self, lhs: &T, rhs: &T) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_le_parallelized(lhs, rhs)
    }

    pub fn max_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_max_parallelized(lhs, rhs)
    }

    pub fn min_parallelized<T>(&self, lhs: &T, rhs: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_min_parallelized(lhs, rhs)
    }
}
