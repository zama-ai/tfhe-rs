use crate::integer::server_key::radix_parallel::bit_extractor::BitExtractor;
use crate::integer::{IntegerRadixCiphertext, RadixCiphertext};
use crate::shortint::ciphertext::Ciphertext;
use crate::shortint::parameters::NoiseLevel;
use crate::shortint::server_key::{LookupTableOwned, ManyLookupTableOwned};
use std::ops::Range;

use super::super::ServerKey;
use super::shift::BarrelShifterOperation;
use rayon::prelude::*;

// This may become its own thing to abstract the use of many many_luts
// or a vec of lut when it's not possible
enum ManyLutStrategy {
    ManyLut(ManyLookupTableOwned),
    Classical(Vec<LookupTableOwned>),
}

impl ManyLutStrategy {
    pub fn execute(&self, server_key: &ServerKey, input: &Ciphertext) -> Vec<Ciphertext> {
        match self {
            Self::ManyLut(many_lut) => server_key.key.apply_many_lookup_table(input, many_lut),
            Self::Classical(luts) => {
                let mut output = vec![input.clone(); luts.len()];

                output
                    .par_iter_mut()
                    .zip(luts.par_iter())
                    .for_each(|(block, lut)| {
                        server_key.key.apply_lookup_table_assign(block, lut);
                    });

                output
            }
        }
    }
}

impl ServerKey {
    /// Implementation of the barrel shift to shift/rotate blocks
    ///
    /// ct: The ciphertext for which blocks will be shifted/rotated
    /// shift_bits_extractor: Must be configured such that shift bits blocks returned
    ///     are in the first carry bit
    /// d_range: Range of bits to process
    ///     Note that starting from something else than 0
    ///     does not mean that the first 'd_range.start' bits from the
    ///     shift_bits_extractor will be skipped, but rather, the first bit returned
    ///     by the shift_bits_extractor is actually the `d_range.start`
    ///     e.g: d_range = 2.. => the first bit of the shift_bits_extractor is
    ///     actually the bit at index 2
    /// operation: The operation to perform
    pub(super) fn block_barrel_shifter_impl<T>(
        &self,
        ct: &T,
        shift_bits_extractor: &mut BitExtractor<'_>,
        d_range: Range<usize>,
        operation: BarrelShifterOperation,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if d_range.is_empty() {
            return ct.clone();
        }

        assert!(
            self.key
                .max_noise_level
                .validate(NoiseLevel::NOMINAL * 3u64)
                .is_ok(),
            "Parameters must support 2 additions before a PBS"
        );
        assert!(
            ct.blocks().iter().all(|block| self
                .key
                .max_noise_level
                .validate(block.noise_level + NoiseLevel::NOMINAL)
                .is_ok()),
            "Blocks of ciphertext to be shifted has a noise level too high"
        );
        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        let num_blocks = ct.blocks().len();

        let message_after_shift_mut = |input| {
            let control_bit = (input >> message_bits_per_block) % 2;
            let x = input % self.message_modulus().0 as u64;

            if control_bit == 1 {
                0
            } else {
                x
            }
        };
        let carry_for_next_block = |input| {
            let control_bit = (input >> message_bits_per_block) % 2;
            let x = input % self.message_modulus().0 as u64;

            if control_bit == 1 {
                x
            } else {
                0
            }
        };

        let luts = if carry_bits_per_block >= 2 {
            // We can use many lut
            let many_luts = self
                .key
                .generate_many_lookup_table(&[&message_after_shift_mut, &carry_for_next_block]);
            ManyLutStrategy::ManyLut(many_luts)
        } else {
            let luts = vec![
                self.key.generate_lookup_table(message_after_shift_mut),
                self.key.generate_lookup_table(carry_for_next_block),
            ];
            ManyLutStrategy::Classical(luts)
        };

        // For signed data, we do an arithmetic right shift, so the padding block
        // depends on the sign bit
        let padding_block_lut = if T::IS_SIGNED && operation == BarrelShifterOperation::RightShift {
            let lut = self.key.generate_lookup_table(|shift_bit_and_last_block| {
                let last_block = shift_bit_and_last_block % self.message_modulus().0 as u64;
                let shift_bit = shift_bit_and_last_block >> self.message_modulus().0.ilog2();
                let sign_bit_pos = self.message_modulus().0.ilog2() - 1;
                if shift_bit == 1 {
                    let sign_bit = (last_block >> sign_bit_pos) & 1;
                    (self.message_modulus().0 - 1) as u64 * sign_bit
                } else {
                    0
                }
            });
            Some(lut)
        } else {
            None
        };

        const MSG_INDEX: usize = 0;
        const CARRY_INDEX: usize = 1;
        let mut padding_block = self.key.create_trivial(0);
        let mut current_blocks = ct.blocks().to_vec();
        let mut d = d_range.start;
        while let Some(shift_bit) = shift_bits_extractor.next() {
            assert!(current_blocks.iter().all(|block| {
                self.key
                    .max_noise_level
                    .validate(block.noise_level + shift_bit.noise_level())
                    .is_ok()
            }));

            let mut messages_and_carries = Vec::with_capacity(current_blocks.len());
            rayon::scope(|s| {
                s.spawn(|_| {
                    current_blocks
                        .par_iter_mut()
                        .map(|block| {
                            self.key.unchecked_add_assign(block, &shift_bit);
                            luts.execute(self, block)
                        })
                        .collect_into_vec(&mut messages_and_carries);
                });

                if d < d_range.end - 1 {
                    s.spawn(|_| {
                        // Prepare the next batch of shift bits while we are doing a round
                        shift_bits_extractor.prepare_next_batch();
                    });
                }

                if T::IS_SIGNED && operation == BarrelShifterOperation::RightShift {
                    s.spawn(|_| {
                        let mut tmp = self
                            .key
                            .unchecked_add(&shift_bit, ct.blocks().last().unwrap());
                        self.key.apply_lookup_table_assign(
                            &mut tmp,
                            padding_block_lut.as_ref().unwrap(),
                        );

                        padding_block = tmp;
                    });
                }
            });

            // copy messages
            for i in 0..num_blocks {
                current_blocks[i].clone_from(&messages_and_carries[i][MSG_INDEX]);
            }

            // align carries
            match operation {
                BarrelShifterOperation::LeftShift => {
                    messages_and_carries.rotate_right(1 << d);
                    for block_that_wrapped in &mut messages_and_carries[..1 << d] {
                        block_that_wrapped[CARRY_INDEX].clone_from(&padding_block);
                    }
                }
                BarrelShifterOperation::RightShift => {
                    messages_and_carries.rotate_left(1 << d);
                    let blocks_that_wrapped = &mut messages_and_carries[num_blocks - (1 << d)..];
                    for block_that_wrapped in blocks_that_wrapped {
                        block_that_wrapped[CARRY_INDEX].clone_from(&padding_block);
                    }
                }
                BarrelShifterOperation::LeftRotate => {
                    messages_and_carries.rotate_right(1 << d);
                }
                BarrelShifterOperation::RightRotate => {
                    messages_and_carries.rotate_left(1 << d);
                }
            }

            for i in 0..num_blocks {
                self.key.unchecked_add_assign(
                    &mut current_blocks[i],
                    &messages_and_carries[i][CARRY_INDEX],
                );
            }

            d += 1;
            if d >= d_range.end {
                break;
            }
        }

        // Reset noise due to last add
        current_blocks
            .par_iter_mut()
            .for_each(|block| self.key.message_extract_assign(block));

        T::from_blocks(current_blocks)
    }

    /// Shifts/Rotates blocks of the `ct` by the specified `amount`
    fn block_barrel_shifter<T>(
        &self,
        ct: &T,
        amount: &RadixCiphertext,
        operation: BarrelShifterOperation,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        let num_blocks = ct.blocks().len();

        // 1 bit for the shift control
        // 1 another for many lut setting
        assert!(carry_bits_per_block >= 2);

        let mut max_num_bits_that_tell_shift = num_blocks.ilog2() as u64;
        // This effectively means, that if the block parameters
        // give a total_nb_bits that is not a power of two,
        // then the behaviour of shifting won't be the same
        // if shift >= total_nb_bits compared to when total_nb_bits
        // is a power of two, as will 'capture' more bits in `shift_bits`
        if !num_blocks.is_power_of_two() {
            max_num_bits_that_tell_shift += 1;
        }

        // Extracts bits and put them in the bit index 2 (=> bit number 3)
        // so that it is already aligned to the correct position of the cmux input
        // and we reduce noise growth
        let mut shift_bit_extractor = BitExtractor::with_final_offset(
            &amount.blocks,
            self,
            message_bits_per_block as usize,
            2,
        );
        shift_bit_extractor.prepare_all_bits();

        self.block_barrel_shifter_impl(
            ct,
            &mut shift_bit_extractor,
            0..max_num_bits_that_tell_shift as usize,
            operation,
        )
    }

    pub fn unchecked_block_rotate_right<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::RightRotate)
    }

    pub fn unchecked_block_rotate_left<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::LeftRotate)
    }

    pub fn unchecked_block_shift_right<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::RightShift)
    }

    pub fn unchecked_block_shift_left<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::LeftShift)
    }

    pub fn smart_block_rotate_right<T>(&self, ct: &mut T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::RightRotate)
    }

    pub fn smart_block_rotate_left<T>(&self, ct: &mut T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::LeftRotate)
    }

    pub fn smart_block_shift_right<T>(&self, ct: &mut T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::RightShift)
    }

    pub fn smart_block_shift_left<T>(&self, ct: &mut T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };
        self.block_barrel_shifter(ct, amount, BarrelShifterOperation::LeftShift)
    }

    pub fn block_rotate_right<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_ct;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };
        self.block_barrel_shifter(lhs, amount, BarrelShifterOperation::RightRotate)
    }

    pub fn block_rotate_left<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_ct;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };
        self.block_barrel_shifter(lhs, amount, BarrelShifterOperation::LeftRotate)
    }

    pub fn block_shift_right<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_ct;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };
        self.block_barrel_shifter(lhs, amount, BarrelShifterOperation::RightShift)
    }

    pub fn block_shift_left<T>(&self, ct: &T, amount: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_ct;
        let lhs = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            self.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };
        self.block_barrel_shifter(lhs, amount, BarrelShifterOperation::LeftShift)
    }
}
