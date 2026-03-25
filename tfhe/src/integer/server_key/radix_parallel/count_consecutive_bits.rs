use crate::integer::prelude::ServerKeyDefaultCMux;
use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};
use crate::integer::{BooleanBlock, IntegerCiphertext, RadixCiphertext, ServerKey};
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};
use rayon::prelude::*;

impl ServerKey {
    pub(crate) fn count_consecutive_bits_2_2_unsigned(
        &self,
        in_ct: &RadixCiphertext,
        direction: Direction,
        bit_value: BitValue,
    ) -> RadixCiphertext {
        assert_eq!(self.message_modulus(), MessageModulus(4));
        assert_eq!(self.carry_modulus(), CarryModulus(4));

        let input_num_bits = 2 * in_ct.blocks.len();

        // output
        let num_output_bits = (input_num_bits as f64 + 1.).log2().ceil() as usize;

        let num_output_blocks = num_output_bits.div_ceil(2);

        let CountConsecutiveBitsResult { flag, mut digits } =
            self.unchecked_count_consecutive_bits_2_2_unsigned(in_ct, direction, bit_value);

        digits.resize(num_output_blocks, self.key.create_trivial(0));

        let true_ct = RadixCiphertext::from_blocks(digits);

        let condition = BooleanBlock::new_unchecked(flag);

        self.if_then_else_parallelized(&condition, &true_ct, input_num_bits as u64)
    }

    // If there is at least one non zero/one bit in the input:
    // - flag is 1
    // - digits is the number of trailing/leading zeros/ones of the input
    // Otherwise, the flag and the digits are equal to 0
    //
    // Let's explain how the algorithm works for leading zeros.
    // Let's suppose we have a 64 bits input and
    //    the input is not 0 (this case works a bit differently).
    // The result is on 6 bits grouped by 2 (b5_b4, b3_b2, b1_b0)
    //
    // b5_b4 is the index of the first (starting from MSB) group of 16 bits
    //     which has (at least) one bit equal to 1.
    // (example, if b5_b4=0, then leading_zeros < 16 thus (at least) one of the 16 MSB is not 0).
    // (example, if b5_b4=1, then 16 <= leading_zeros < 32 thus the 16 MSB are
    //                             all 0 and (at least) one the one of the 16 next MSB is not 0).
    //
    // In this group of 16 bits:
    //  - b3_b2 is is the index of the first (starting from MSB) group of 4 bits which has (at
    //    least) one bit equal to 1
    // In this group of 4 bits:
    //  - b1_b0 is is the index of the first (starting from MSB) bit equal to 1
    //
    // This is the top down view
    //
    // In the algorithm, we use the bottom up view.
    // We compute the "b1_b0" of each group of 4 bits
    //   and a boolean flag to know if (at least) one of the bits are not 0.
    //
    // We then group by 16 bits.
    // We compute the "b3_b2" of each group.
    // It is the index of the first (starting from MSB) group of 4 with a non zero flag.
    // We select its "b1_b0" among the 4 computed in the previous step.
    // We now have "b3_b2_b1_b0" for each group of 16.
    // We also need a flag to know if (at least) one of the bits are not 0.
    //
    // We now have 4 groups of 16.
    // "b5_b4" is the index of the first (starting from MSB) group of 16 with a non zero flag.
    // We select its "b3_b2_b1_b0" among the 4 computed in the previous step.
    // We also compute a flag to know if (at least) one of the bits are not 0.
    //
    // We now have the final result
    pub(crate) fn unchecked_count_consecutive_bits_2_2_unsigned(
        &self,
        in_ct: &RadixCiphertext,
        direction: Direction,
        bit_value: BitValue,
    ) -> CountConsecutiveBitsResult {
        assert_eq!(self.message_modulus(), MessageModulus(4));
        assert_eq!(self.carry_modulus(), CarryModulus(4));

        if in_ct.blocks().is_empty() {
            return CountConsecutiveBitsResult {
                flag: self.key.create_trivial(0),
                digits: Vec::new(),
            };
        }

        let num_blocks_after_init = in_ct.blocks().len() as f64 / 2_f64;

        let reductions_depth = num_blocks_after_init.log(4_f64).ceil() as usize;

        let mut up_scale_digits: bool = reductions_depth % 2 == 1;

        let digit_out_scale_init = if up_scale_digits { 2 } else { 0 };

        let mut state: Vec<BlockState> = match direction {
            Direction::Trailing => in_ct
                .blocks()
                .par_chunks(2)
                .map(|chunk| self.pack_blocks_by_pair(chunk, direction, bit_value))
                .enumerate()
                .map(|(index, ct)| {
                    self.initial_state(&ct, index % 4, digit_out_scale_init, direction, bit_value)
                })
                .collect(),
            // par_rchunk(2).enumerate().rev() to:
            // - get a reverse index without changing the order
            // - align chunk on the most significant blocks (if the last chunk has only one element)
            Direction::Leading => in_ct
                .blocks()
                .par_rchunks(2)
                .map(|chunk| self.pack_blocks_by_pair(chunk, direction, bit_value))
                .enumerate()
                .rev()
                .map(|(reverse_index, ct)| {
                    self.initial_state(
                        &ct,
                        reverse_index % 4,
                        digit_out_scale_init,
                        direction,
                        bit_value,
                    )
                })
                .collect(),
        };

        while state.len() != 1 {
            up_scale_digits = !up_scale_digits;

            state = match direction {
                Direction::Trailing => state
                    .par_chunks(4)
                    .enumerate()
                    .map(|(index, chunk)| {
                        self.reduce_blocks(chunk, index % 4, up_scale_digits, direction)
                    })
                    .collect(),
                // par_rchunk(4).enumerate().rev() to:
                // - get a reverse index without changing the order
                // - align chunk on the most significant blocks (if the last chunk does not have 4
                //   elements)
                Direction::Leading => state
                    .par_rchunks(4)
                    .enumerate()
                    .rev()
                    .map(|(reverse_index, chunk)| {
                        self.reduce_blocks(chunk, reverse_index % 4, up_scale_digits, direction)
                    })
                    .collect(),
            };
        }

        assert!(!up_scale_digits);

        let BlockState {
            flag,
            digits: digits_state,
        } = state.pop().unwrap();

        CountConsecutiveBitsResult {
            flag,
            digits: digits_state.select(self, up_scale_digits, direction),
        }
    }

    fn pack_blocks_by_pair(
        &self,
        chunk: &[Ciphertext],
        direction: Direction,
        bit_value: BitValue,
    ) -> Ciphertext {
        match chunk {
            [chunk0, chunk1] => {
                // chunk 1 is most significant, so we scale it to the carries
                let mut result = self.key.unchecked_scalar_mul(chunk1, 4);

                self.key.unchecked_add_assign(&mut result, chunk0);

                result
            }
            [chunk0] => {
                // We must pad in case the input has a even number of blocks
                // The pad must not change the result
                // This padding value will only have an impact on the final result if all other bits
                // are equal to the given bit_value In this case, we want to pad
                // with bits equal to the bit_value so the result is flag = 0,
                // digits= [0, ..., 0] as specified
                let padding_value = match bit_value {
                    BitValue::Zero => 0,
                    BitValue::One => 3,
                };

                match direction {
                    // We put the padding in the MSB
                    Direction::Trailing => self.key.unchecked_scalar_add(chunk0, 4 * padding_value),
                    // We put the padding in the LSB
                    Direction::Leading => {
                        let mut result = self.key.unchecked_scalar_mul(chunk0, 4);
                        self.key
                            .unchecked_scalar_add_assign(&mut result, padding_value);
                        result
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn initial_state(
        &self,
        ct: &Ciphertext,
        flag_out_scale: usize,
        digit_out_scale: usize,
        direction: Direction,
        bit_value: BitValue,
    ) -> BlockState {
        let (flag, new_digit) = rayon::join(
            || {
                let lut_non_full_flag = self.lut_non_full_flag(flag_out_scale, bit_value);

                self.key.apply_lookup_table(ct, &lut_non_full_flag)
            },
            || {
                let lut_new_digit = self.lut_new_digit_init(digit_out_scale, direction, bit_value);

                self.key.apply_lookup_table(ct, &lut_new_digit)
            },
        );

        BlockState {
            flag,
            digits: DigitsUnselected {
                new_digit,
                old_digits_to_select: Vec::new(),
            },
        }
    }

    // Put blocks of n digits from a slice to groups of 4
    //
    // Each group of 4 is reduced to a single block of (n+1) digits as such:
    // The fist block with a non zero flag is selected.
    // The new digits are the digits of this block to which we add the index of this selected block
    fn reduce_blocks(
        &self,
        blocks: &[BlockState],
        out_flag_scale: usize,
        up_scale_digits: bool,
        direction: Direction,
    ) -> BlockState {
        let (in_flags, digits): (Vec<_>, Vec<_>) = blocks
            .iter()
            .map(
                |BlockState {
                     flag,
                     digits: digits_state,
                 }| (flag, digits_state),
            )
            .unzip();

        // old digits are one step behind the flag and new_digit
        // so opposite scaling
        let up_scale_old_digits = !up_scale_digits;

        let ((flag, new_digit), old_digits_to_select) = rayon::join(
            || self.build_new_flag_and_digit(out_flag_scale, up_scale_digits, &in_flags),
            || self.reduce_digit_states(&digits, up_scale_old_digits, direction),
        );

        BlockState {
            flag,
            digits: DigitsUnselected {
                new_digit,
                old_digits_to_select,
            },
        }
    }

    // The input is expected to be (at most) 4 binary flags, scaled by 0, 1, 2, 3 (0_0_0_f, 0_0_f_0,
    // 0_f_0_0, f_0_0_0) The new flag is 0 if all input flags are 0, 1 otherwise
    // The new digit is the scaling of the smallest non zero flag, 0 otherwise
    // The output does not depend on the order of the input flags (as they are all summed)
    fn build_new_flag_and_digit(
        &self,
        out_flag_scale: usize,
        up_scale_digits: bool,
        flags: &[&Ciphertext],
    ) -> (Ciphertext, Ciphertext) {
        let sum_flags = flags.iter().fold(self.key.create_trivial(0), |mut a, b| {
            self.key.unchecked_add_assign(&mut a, b);
            a
        });

        let out_digit_scale = if up_scale_digits { 2 } else { 0 };

        rayon::join(
            || {
                let lut_non_zero_flag = self.lut_non_zero_flag(out_flag_scale);

                self.key.apply_lookup_table(&sum_flags, &lut_non_zero_flag)
            },
            || {
                let lut_new_digit = self.lut_new_digit_from_sum_flags(out_digit_scale);

                self.key.apply_lookup_table(&sum_flags, &lut_new_digit)
            },
        )
    }

    fn reduce_digit_states(
        &self,
        states: &[&DigitsUnselected],
        up_scale_digits: bool,
        direction: Direction,
    ) -> Vec<DigitUnselected> {
        // we'll want to select one of the lists of digits (Vec<Ciphertext>)
        // we'll want unselected_list_of_digits[new_digit]
        let unselected_list_of_digits: Vec<Vec<Ciphertext>> = states
            .par_iter()
            .map(|digits_unselected| digits_unselected.select(self, up_scale_digits, direction))
            .collect();

        // after transpose, each element is an UnselectedDigit (i.e. a list of digits to select
        // from) we'll want
        // [
        //     list_of_unselected_digits[0][new_digit],
        //     list_of_unselected_digits[1][new_digit],
        //     ...
        // ]
        let list_of_unselected_digits = transpose(unselected_list_of_digits);

        list_of_unselected_digits
            .into_iter()
            .map(|digits_to_select_from| DigitUnselected {
                digits_to_select_from,
            })
            .collect()
    }

    fn select_old_digit_lut(
        &self,
        up_scale_digits: bool,
        selector: usize,
    ) -> crate::shortint::server_key::LookupTable<Vec<u64>> {
        self.key.generate_lookup_table(|x: u64| {
            let in_carries = x >> 2;
            let in_message = x & 3;

            // The input of the resulting LUT is supposed to have the old/new digits in
            // carry/message depending on up_scale_digits
            let (old_digit, new_digit) = if up_scale_digits {
                (in_message, in_carries)
            } else {
                (in_carries, in_message)
            };

            if new_digit == selector as u64 {
                if up_scale_digits {
                    old_digit << 2
                } else {
                    old_digit
                }
            } else {
                0
            }
        })
    }

    // build a lut which returns
    // `0` if the 4 bits input is full of the bit_value (0000 for Zero or 1111 for One)
    // `1 << out_scale` otherwise
    fn lut_non_full_flag(&self, out_scale: usize, bit_value: BitValue) -> LookupTableOwned {
        let full_value = match bit_value {
            BitValue::Zero => 0,
            BitValue::One => 15,
        };

        self.key
            .generate_lookup_table(|x| u64::from(x != full_value) << out_scale)
    }

    fn lut_non_zero_flag(&self, out_scale: usize) -> LookupTableOwned {
        self.key
            .generate_lookup_table(|x| u64::from(x != 0) << out_scale)
    }

    // build a lut which
    // return `0` if the input is full of the bit_value (0000 for Zero or 1111 for One)
    // otherwise, return the trailing/leading zeros/ones of the 4 bits input, scaled by `out_scale`
    fn lut_new_digit_init(
        &self,
        out_scale: usize,
        direction: Direction,
        bit_value: BitValue,
    ) -> LookupTableOwned {
        self.key.generate_lookup_table(|x: u64| {
            let full_value = match bit_value {
                BitValue::Zero => 0,
                BitValue::One => 15,
            };

            let input_precision = 4;

            let leading_bits_to_ignore = u64::BITS - input_precision;

            let new_digit = if x == full_value {
                0
            } else {
                match (direction, bit_value) {
                    (Direction::Trailing, BitValue::Zero) => x.trailing_zeros(),
                    (Direction::Trailing, BitValue::One) => x.trailing_ones(),
                    (Direction::Leading, BitValue::Zero) => {
                        (x << leading_bits_to_ignore).leading_zeros()
                    }
                    (Direction::Leading, BitValue::One) => {
                        (x << leading_bits_to_ignore).leading_ones()
                    }
                }
            };

            (new_digit as u64) << out_scale
        })
    }

    // build a lut
    // the input is expected to the sum of 4 binary flags, scaled by 0, 1, 2, 3 (0_0_0_f0 + 0_0_f1_0
    // + 0_f2_0_0 + f3_0_0_0 = f3_f2_f1_f0) if all the flags are 0, the result if 0
    // otherwise, the result is the index of the first of these flag which is not 0, starting by f0.
    // this function is used in all cases (trailing/leading zeros/ones) in all steps expect the
    // first one
    fn lut_new_digit_from_sum_flags(&self, out_scale: usize) -> LookupTableOwned {
        self.key.generate_lookup_table(|x: u64| {
            let new_digit = if x == 0 { 0 } else { x.trailing_zeros() as u64 };

            new_digit << out_scale
        })
    }
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if v.is_empty() {
        return vec![];
    }
    let num_cols = v[0].len();
    let mut row_iterators: Vec<_> = v.into_iter().map(|row| row.into_iter()).collect();
    (0..num_cols)
        .map(|_| {
            row_iterators
                .iter_mut()
                .map(|row_iterator| row_iterator.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

struct BlockState {
    flag: Ciphertext,
    digits: DigitsUnselected,
}

// When doing the reduction, we want to use the new_digit to select each unselected_digit
// We then add the new digit to the end of the list
struct DigitsUnselected {
    new_digit: Ciphertext,
    old_digits_to_select: Vec<DigitUnselected>,
}

impl DigitsUnselected {
    fn select(
        &self,
        sk: &ServerKey,
        up_scale_digits: bool,
        direction: Direction,
    ) -> Vec<Ciphertext> {
        let Self {
            new_digit,
            old_digits_to_select,
        } = self;

        let mut result: Vec<_> = old_digits_to_select
            .par_iter()
            .map(|digit| digit.select(new_digit, sk, up_scale_digits, direction))
            .collect();

        result.push(new_digit.clone());

        result
    }
}

// Stores a list of (at most) 4 ciphertexts each storing a digit in carries or messages
// This type is meant to be reduced to a single selected digit
struct DigitUnselected {
    digits_to_select_from: Vec<Ciphertext>,
}

impl DigitUnselected {
    fn select(
        &self,
        selector: &Ciphertext,
        sk: &ServerKey,
        up_scale_digits: bool,
        direction: Direction,
    ) -> Ciphertext {
        let digits_to_select_from: Vec<&Ciphertext> = match direction {
            Direction::Trailing => self.digits_to_select_from.iter().collect(),
            Direction::Leading => self.digits_to_select_from.iter().rev().collect(),
        };

        // Computation is sum_i( if i==selector { digits_to_select_from[i] } else {0} )
        // Which gives digits_to_select_from[selector]
        let mut result = digits_to_select_from
            .par_iter()
            .enumerate()
            .map(|(i, old_digit)| {
                let sum = sk.key.unchecked_add(old_digit, selector);

                let acc = sk.select_old_digit_lut(up_scale_digits, i);

                sk.key.apply_lookup_table(&sum, &acc)
            })
            .reduce(
                || sk.key.create_trivial(0),
                |mut sum: Ciphertext, new: Ciphertext| {
                    sk.key.unchecked_add_assign(&mut sum, &new);

                    sum
                },
            );

        result.degree = if up_scale_digits {
            Degree(12)
        } else {
            Degree(3)
        };

        result
    }
}

pub(crate) struct CountConsecutiveBitsResult {
    #[allow(unused)]
    pub(crate) flag: Ciphertext,
    pub(crate) digits: Vec<Ciphertext>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::{ClientKey, IntegerKeyKind, RadixCiphertext};
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_unchecked_new_count_consecutive_bits_trivial_input_param_message_2_carry_2() {
        let param = PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;

        let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

        for direction in [Direction::Leading, Direction::Trailing] {
            for bit_value in [BitValue::Zero, BitValue::One] {
                for num_blocks in 1..64 {
                    let num_bits = 2 * num_blocks;

                    println!("num_bits: {num_bits}",);

                    for target_result in 0..=num_bits {
                        for _ in 0..10 {
                            test_one_random(
                                &cks,
                                &sks,
                                num_blocks,
                                direction,
                                bit_value,
                                target_result,
                            );
                        }
                    }
                }
            }
        }
    }

    fn test_one_random(
        cks: &ClientKey,
        sks: &ServerKey,
        num_blocks: usize,
        direction: Direction,
        bit_value: BitValue,
        target_result: usize,
    ) {
        let num_bits = 2 * num_blocks;

        let message = build_number(num_bits, target_result, direction, bit_value);

        let (expected_flag, expected_result) =
            expected_result(num_bits, message, direction, bit_value);

        let (flag, result) =
            get_result_for_trivial(cks, sks, num_blocks, message, direction, bit_value);

        assert_eq!(expected_flag, flag);

        if target_result == num_bits {
            assert!(!expected_flag);

            assert_eq!(expected_result, 0);
        } else {
            assert_eq!(target_result as u64, expected_result);
        }

        assert_eq!(expected_result, result);
    }

    fn expected_result(
        num_bits: usize,
        message: u128,
        direction: Direction,
        bit_value: BitValue,
    ) -> (bool, u64) {
        let full_value = match bit_value {
            BitValue::Zero => 0,
            BitValue::One => (1 << num_bits) - 1,
        };

        if message == full_value {
            (false, 0)
        } else {
            let leading_bits_to_ignore = 128 - num_bits;

            let expected_result = match (direction, bit_value) {
                (Direction::Trailing, BitValue::Zero) => message.trailing_zeros(),
                (Direction::Trailing, BitValue::One) => message.trailing_ones(),
                (Direction::Leading, BitValue::Zero) => {
                    (message << leading_bits_to_ignore).leading_zeros()
                }
                (Direction::Leading, BitValue::One) => {
                    (message << leading_bits_to_ignore).leading_ones()
                }
            };

            (true, expected_result as u64)
        }
    }

    fn build_number(
        num_bits: usize,
        target_result: usize,
        direction: Direction,
        bit_value: BitValue,
    ) -> u128 {
        let full_bits = num_bits - target_result;

        let message: u128 = if full_bits == 0 {
            0
        } else {
            match direction {
                Direction::Leading => {
                    (1_u128 << (full_bits - 1)) + thread_rng().gen_range(0..1 << (full_bits - 1))
                }
                Direction::Trailing => {
                    let full_number =
                        1_u128 + (thread_rng().gen_range(0..1 << (full_bits - 1)) << 1);
                    full_number << target_result
                }
            }
        };

        match bit_value {
            BitValue::Zero => message,
            //complement
            BitValue::One => (1_u128 << num_bits) - 1 - message,
        }
    }

    fn get_result_for_trivial(
        cks: &ClientKey,
        sks: &ServerKey,
        num_blocks: usize,
        message: u128,
        direction: Direction,
        bit_value: BitValue,
    ) -> (bool, u64) {
        let input: RadixCiphertext = sks.create_trivial_radix(message, num_blocks);

        let CountConsecutiveBitsResult { flag, digits } =
            sks.unchecked_count_consecutive_bits_2_2_unsigned(&input, direction, bit_value);

        let flag = match cks.key.decrypt_message_and_carry(&flag) {
            0 => false,
            1 => true,
            _ => panic!(),
        };

        let mut result = 0;
        for (i, digit) in digits.iter().enumerate() {
            let digit = cks.key.decrypt_message_and_carry(digit);

            result += digit << (2 * i);
        }

        (flag, result)
    }
}
