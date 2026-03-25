use crate::integer::server_key::radix_parallel::ilog2::{BitValue, Direction};
use crate::integer::{IntegerRadixCiphertext, ServerKey};
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus};
use arrayvec::ArrayVec;
use rayon::prelude::*;

impl ServerKey {
    pub(crate) fn unchecked_count_consecutive_bits<T>(
        &self,
        in_ct: &T,
        direction: Direction,
        bit_value: BitValue,
    ) -> CountConsecutiveBitsResult
    where
        T: IntegerRadixCiphertext,
    {
        assert_eq!(self.message_modulus(), MessageModulus(4));
        assert_eq!(self.carry_modulus(), CarryModulus(4));

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
                let mut result = self.key.unchecked_scalar_mul(chunk1, 4);

                self.key.unchecked_add_assign(&mut result, chunk0);

                result
            }
            [chunk0] => {
                let padding_value = match bit_value {
                    BitValue::Zero => 0,
                    BitValue::One => 3,
                };

                match direction {
                    Direction::Trailing => self.key.unchecked_scalar_add(chunk0, 4 * padding_value),
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
                let lut_non_zero_flag = self.lut_non_full_flag(flag_out_scale, bit_value);
                self.key.apply_lookup_table(ct, &lut_non_zero_flag)
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
                old_digits_to_select: ArrayVec::new(),
            },
        }
    }

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
    ) -> ArrayVec<DigitUnselected, 4> {
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
        target_new_digit: usize,
    ) -> crate::shortint::server_key::LookupTable<Vec<u64>> {
        self.key.generate_lookup_table(|x: u64| {
            let in_carries = x >> 2;
            let in_message = x & 3;

            let (old_digit, new_digit) = if up_scale_digits {
                (in_message, in_carries)
            } else {
                (in_carries, in_message)
            };

            if new_digit == target_new_digit as u64 {
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

            let leading_bits_to_ignore = 64 - 4;

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

    fn lut_new_digit_from_sum_flags(&self, out_scale: usize) -> LookupTableOwned {
        self.key.generate_lookup_table(|x: u64| {
            let new_digit = if x == 0 { 0 } else { x.trailing_zeros() as u64 };

            new_digit << out_scale
        })
    }
}

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<ArrayVec<T, 4>> {
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
                .collect::<ArrayVec<T, 4>>()
        })
        .collect()
}

struct BlockState {
    flag: Ciphertext,
    digits: DigitsUnselected,
}

struct DigitsUnselected {
    new_digit: Ciphertext,
    old_digits_to_select: ArrayVec<DigitUnselected, 4>,
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

struct DigitUnselected {
    digits_to_select_from: ArrayVec<Ciphertext, 4>,
}

impl DigitUnselected {
    fn select(
        &self,
        selector: &Ciphertext,
        sk: &ServerKey,
        up_scale_digits: bool,
        direction: Direction,
    ) -> Ciphertext {
        let digits_to_select_from: ArrayVec<&Ciphertext, 4> = match direction {
            Direction::Trailing => self.digits_to_select_from.iter().collect(),
            Direction::Leading => self.digits_to_select_from.iter().rev().collect(),
        };

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
    fn test_unchecked_new_leading_zeroes() {
        let param = PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;

        let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

        for direction in [Direction::Leading, Direction::Trailing] {
            for bit_value in [BitValue::Zero, BitValue::One] {
                for num_blocks in 1..64 {
                    let num_bits = 2 * num_blocks;

                    println!("\x1b[31mnum_bits\x1b[0m: {num_bits}",);

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

        let (flag, result) = get_result(cks, sks, num_blocks, message, direction, bit_value);

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

    fn get_result(
        cks: &ClientKey,
        sks: &ServerKey,
        num_blocks: usize,
        message: u128,
        direction: Direction,
        bit_value: BitValue,
    ) -> (bool, u64) {
        let input: RadixCiphertext = sks.create_trivial_radix(message, num_blocks);

        let CountConsecutiveBitsResult { flag, digits } =
            sks.unchecked_count_consecutive_bits(&input, direction, bit_value);

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
