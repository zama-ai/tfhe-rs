use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::server_key::radix_parallel::bit_extractor::BitExtractor;
use crate::integer::ServerKey;
use rayon::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BarrelShifterOperation {
    LeftRotate,
    LeftShift,
    RightShift,
    RightRotate,
}

impl BarrelShifterOperation {
    pub(super) fn invert_direction(self) -> Self {
        match self {
            Self::LeftRotate => Self::RightRotate,
            Self::LeftShift => Self::RightShift,
            Self::RightShift => Self::LeftShift,
            Self::RightRotate => Self::LeftRotate,
        }
    }
}

impl ServerKey {
    //======================================================================
    //                Shift Right
    //======================================================================

    pub fn unchecked_right_shift_parallelized<T>(&self, ct_left: &T, shift: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_right_shift_assign_parallelized(&mut result, shift);
        result
    }

    pub fn unchecked_right_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_shift_rotate_bits_assign(ct, shift, BarrelShifterOperation::RightShift);
    }

    pub fn smart_right_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &mut RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_right_shift_assign_parallelized(ct, shift);
    }

    pub fn smart_right_shift_parallelized<T>(&self, ct: &mut T, shift: &mut RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_right_shift_parallelized(ct, shift)
    }

    pub fn right_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, shift)
            }
            (false, false) => {
                tmp_rhs = shift.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_right_shift_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a right shift by an encrypted amount
    ///
    /// The result is returned as a new ciphertext.
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
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    /// let shift_ct = cks.encrypt(shift as u64);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.right_shift_parallelized(&ct, &shift_ct);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn right_shift_parallelized<T>(&self, ct: &T, shift: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.right_shift_assign_parallelized(&mut ct_res, shift);
        ct_res
    }

    //======================================================================
    //                Shift Left
    //======================================================================

    /// left shift by and encrypted amount
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    pub fn unchecked_left_shift_parallelized<T>(&self, ct_left: &T, shift: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_left_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// left shift by and encrypted amount
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    pub fn unchecked_left_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_shift_rotate_bits_assign(ct, shift, BarrelShifterOperation::LeftShift);
    }

    pub fn smart_left_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &mut RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_left_shift_assign_parallelized(ct, shift);
    }

    pub fn smart_left_shift_parallelized<T>(&self, ct: &mut T, shift: &mut RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        rayon::join(
            || {
                if !ct.block_carries_are_empty() {
                    self.full_propagate_parallelized(ct);
                }
            },
            || {
                if !shift.block_carries_are_empty() {
                    self.full_propagate_parallelized(shift);
                }
            },
        );
        self.unchecked_left_shift_parallelized(ct, shift)
    }

    pub fn left_shift_assign_parallelized<T>(&self, ct: &mut T, shift: &RadixCiphertext)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ct.block_carries_are_empty(),
            shift.block_carries_are_empty(),
        ) {
            (true, true) => (ct, shift),
            (true, false) => {
                tmp_rhs = shift.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ct, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ct);
                (ct, shift)
            }
            (false, false) => {
                tmp_rhs = shift.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ct),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ct, &tmp_rhs)
            }
        };

        self.unchecked_left_shift_assign_parallelized(lhs, rhs);
    }

    /// Computes homomorphically a left shift by an encrypted amount.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(shift as u64);
    ///
    /// // Compute homomorphically a left shift:
    /// let ct_res = sks.left_shift_parallelized(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn left_shift_parallelized<T>(&self, ct: &T, shift: &RadixCiphertext) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.left_shift_assign_parallelized(&mut ct_res, shift);
        ct_res
    }

    /// Does a rotation/shift of bits of the `ct` by the specified `amount`
    ///
    /// Input must not have carries
    pub(super) fn unchecked_shift_rotate_bits_assign<T>(
        &self,
        ct: &mut T,
        amount: &RadixCiphertext,
        operation: BarrelShifterOperation,
    ) where
        T: IntegerRadixCiphertext,
    {
        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        assert!(carry_bits_per_block >= message_bits_per_block);

        let num_bits = ct.blocks().len() * message_bits_per_block as usize;
        let mut max_num_bits_that_tell_shift = num_bits.ilog2() as u64;
        // This effectively means, that if the block parameters
        // give a total_nb_bits that is not a power of two,
        // then the behaviour of shifting won't be the same
        // if shift >= total_nb_bits compared to when total_nb_bits
        // is a power of two, as will 'capture' more bits in `shift_bits`
        if !num_bits.is_power_of_two() {
            max_num_bits_that_tell_shift += 1;
        }

        if message_bits_per_block == 1 {
            let mut shift_bit_extractor = BitExtractor::with_final_offset(
                &amount.blocks,
                self,
                message_bits_per_block as usize,
                message_bits_per_block as usize,
            );

            // If blocks encrypt one bit, then shifting bits is just shifting blocks
            let result = self.block_barrel_shifter_impl(
                ct,
                &mut shift_bit_extractor,
                0..max_num_bits_that_tell_shift as usize,
                // Our blocks are stored in little endian order
                operation.invert_direction(),
            );

            *ct = result;
        } else if message_bits_per_block.is_power_of_two() {
            let result = self.barrel_shift_bits_pow2_block_modulus(
                ct,
                amount,
                operation,
                max_num_bits_that_tell_shift as usize,
            );
            *ct = result;
        } else {
            self.bit_barrel_shifter(ct, amount, operation);
        }
    }

    /// Does a rotation/shift of bits of the `ct` by the specified `amount`
    ///
    /// Uses a barrel shifter implementation
    ///
    /// # Note
    ///
    /// This only works for parameters where blocks encrypts a number of bits
    /// of message that is a power of 2 (e.g. 1 bit, 2 bit, 4 bits, but not 3 bits)
    pub(super) fn barrel_shift_bits_pow2_block_modulus<T>(
        &self,
        ct: &T,
        amount: &RadixCiphertext,
        operation: BarrelShifterOperation,
        max_num_bits_that_tell_shift: usize,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if amount.blocks.is_empty() || ct.blocks().is_empty() {
            return ct.clone();
        }

        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        assert!(carry_bits_per_block >= message_bits_per_block);
        assert!(message_bits_per_block.is_power_of_two());

        if ct.blocks().len() == 1 {
            let lut = self
                .key
                .generate_lookup_table_bivariate(|input, first_shift_block| {
                    let shift_within_block = first_shift_block % message_bits_per_block;

                    match operation {
                        BarrelShifterOperation::LeftShift => {
                            (input << shift_within_block) % self.message_modulus().0
                        }
                        BarrelShifterOperation::LeftRotate => {
                            let shifted = (input << shift_within_block) % self.message_modulus().0;
                            let wrapped = input >> (message_bits_per_block - shift_within_block);
                            shifted | wrapped
                        }
                        BarrelShifterOperation::RightRotate => {
                            let shifted = input >> shift_within_block;
                            let wrapped = (input << (message_bits_per_block - shift_within_block))
                                % self.message_modulus().0;
                            wrapped | shifted
                        }
                        BarrelShifterOperation::RightShift => {
                            if T::IS_SIGNED {
                                let sign_bit_pos = message_bits_per_block - 1;
                                let sign_bit = (input >> sign_bit_pos) & 1;
                                let padding_block = (self.message_modulus().0 - 1) * sign_bit;

                                // Pad with sign bits to 'simulate' an arithmetic shift
                                let input = (padding_block << message_bits_per_block) | input;
                                (input >> shift_within_block) % self.message_modulus().0
                            } else {
                                input >> shift_within_block
                            }
                        }
                    }
                });

            let block = self.key.unchecked_apply_lookup_table_bivariate(
                &ct.blocks()[0],
                &amount.blocks[0],
                &lut,
            );

            return T::from_blocks(vec![block]);
        }

        let message_for_block =
            self.key
                .generate_lookup_table_bivariate(|input, first_shift_block| {
                    let shift_within_block = first_shift_block % message_bits_per_block;
                    let shift_to_next_block = (first_shift_block / message_bits_per_block) % 2;

                    let b = match operation {
                        BarrelShifterOperation::LeftShift | BarrelShifterOperation::LeftRotate => {
                            (input << shift_within_block) % self.message_modulus().0
                        }
                        BarrelShifterOperation::RightShift
                        | BarrelShifterOperation::RightRotate => {
                            (input >> shift_within_block) % self.message_modulus().0
                        }
                    };

                    if shift_to_next_block == 1 {
                        0
                    } else {
                        b
                    }
                });

        // When doing right shift of a signed ciphertext, we do an arithmetic shift
        // Thus, we need some special luts to be used on the last block
        // (which has the sign bit)
        let message_for_block_right_shift_signed =
            if T::IS_SIGNED && operation == BarrelShifterOperation::RightShift {
                let lut = self
                    .key
                    .generate_lookup_table_bivariate(|input, first_shift_block| {
                        let shift_within_block = first_shift_block % message_bits_per_block;
                        let shift_to_next_block = (first_shift_block / message_bits_per_block) % 2;

                        let sign_bit_pos = message_bits_per_block - 1;
                        let sign_bit = (input >> sign_bit_pos) & 1;
                        let padding_block = (self.message_modulus().0 - 1) * sign_bit;

                        if shift_to_next_block == 1 {
                            padding_block
                        } else {
                            // Pad with sign bits to 'simulate' an arithmetic shift
                            let input = (padding_block << message_bits_per_block) | input;
                            (input >> shift_within_block) % self.message_modulus().0
                        }
                    });
                Some(lut)
            } else {
                None
            };

        // Extracts bits and put them in the bit index 2 (=> bit number 3)
        // so that it is already aligned to the correct position of the cmux input,
        // and we reduce noise growth
        let mut shift_bit_extractor = BitExtractor::with_final_offset(
            &amount.blocks,
            self,
            message_bits_per_block as usize,
            message_bits_per_block as usize,
        );

        let message_for_next_block =
            self.key
                .generate_lookup_table_bivariate(|previous, first_shift_block| {
                    let shift_within_block = first_shift_block % message_bits_per_block;
                    let shift_to_next_block = (first_shift_block / message_bits_per_block) % 2;

                    if shift_to_next_block == 1 {
                        // We get the message part of the previous block
                        match operation {
                            BarrelShifterOperation::LeftShift
                            | BarrelShifterOperation::LeftRotate => {
                                (previous << shift_within_block) % self.message_modulus().0
                            }
                            BarrelShifterOperation::RightShift
                            | BarrelShifterOperation::RightRotate => {
                                (previous >> shift_within_block) % self.message_modulus().0
                            }
                        }
                    } else {
                        // We get the carry part of the previous block
                        match operation {
                            BarrelShifterOperation::LeftShift
                            | BarrelShifterOperation::LeftRotate => {
                                previous >> (message_bits_per_block - shift_within_block)
                            }
                            BarrelShifterOperation::RightShift
                            | BarrelShifterOperation::RightRotate => {
                                (previous << (message_bits_per_block - shift_within_block))
                                    % self.message_modulus().0
                            }
                        }
                    }
                });

        let message_for_next_next_block =
            self.key
                .generate_lookup_table_bivariate(|previous_previous, first_shift_block| {
                    let shift_within_block = first_shift_block % message_bits_per_block;
                    let shift_to_next_block = (first_shift_block / message_bits_per_block) % 2;

                    if shift_to_next_block == 1 {
                        // We get the carry part of the previous block
                        match operation {
                            BarrelShifterOperation::LeftShift
                            | BarrelShifterOperation::LeftRotate => {
                                previous_previous >> (message_bits_per_block - shift_within_block)
                            }
                            BarrelShifterOperation::RightShift
                            | BarrelShifterOperation::RightRotate => {
                                (previous_previous << (message_bits_per_block - shift_within_block))
                                    % self.message_modulus().0
                            }
                        }
                    } else {
                        // Nothing reaches that block
                        0
                    }
                });

        let message_for_next_block_right_shift_signed = if T::IS_SIGNED
            && operation == BarrelShifterOperation::RightShift
        {
            let lut = self
                .key
                .generate_lookup_table_bivariate(|previous, first_shift_block| {
                    let shift_within_block = first_shift_block % message_bits_per_block;
                    let shift_to_next_block = (first_shift_block / message_bits_per_block) % 2;

                    let sign_bit_pos = message_bits_per_block - 1;
                    let sign_bit = (previous >> sign_bit_pos) & 1;
                    let padding_block = (self.message_modulus().0 - 1) * sign_bit;

                    if shift_to_next_block == 1 {
                        // Pad with sign bits to 'simulate' an arithmetic shift
                        let previous = (padding_block << message_bits_per_block) | previous;
                        // We get the message part of the previous block
                        (previous >> shift_within_block) % self.message_modulus().0
                    } else {
                        // We get the carry part of the previous block
                        (previous << (message_bits_per_block - shift_within_block))
                            % self.message_modulus().0
                    }
                });
            Some(lut)
        } else {
            None
        };

        let mut messages = ct.blocks().to_vec();
        let mut messages_for_next_blocks = ct.blocks().to_vec();
        let mut messages_for_next_next_blocks = ct.blocks().to_vec();
        let first_block = &amount.blocks[0];
        let num_blocks = ct.blocks().len();
        rayon::scope(|s| {
            s.spawn(|_| {
                messages.par_iter_mut().enumerate().for_each(|(i, block)| {
                    let lut = if T::IS_SIGNED
                        && operation == BarrelShifterOperation::RightShift
                        && i == num_blocks - 1
                    {
                        message_for_block_right_shift_signed.as_ref().unwrap()
                    } else {
                        &message_for_block
                    };
                    self.key
                        .unchecked_apply_lookup_table_bivariate_assign(block, first_block, lut);
                });
            });

            s.spawn(|_| {
                let range = match operation {
                    BarrelShifterOperation::RightShift => {
                        messages_for_next_blocks[0] = self.key.create_trivial(0);
                        1..num_blocks
                    }
                    BarrelShifterOperation::LeftShift => {
                        messages_for_next_blocks[num_blocks - 1] = self.key.create_trivial(0);
                        0..num_blocks - 1
                    }
                    BarrelShifterOperation::LeftRotate | BarrelShifterOperation::RightRotate => {
                        0..num_blocks
                    }
                };

                let range_len = range.len();
                messages_for_next_blocks[range]
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, block)| {
                        let lut = if T::IS_SIGNED
                            && operation == BarrelShifterOperation::RightShift
                            && i == range_len - 1
                        {
                            message_for_next_block_right_shift_signed.as_ref().unwrap()
                        } else {
                            &message_for_next_block
                        };
                        self.key.unchecked_apply_lookup_table_bivariate_assign(
                            block,
                            first_block,
                            lut,
                        );
                    });
            });

            s.spawn(|_| {
                let range = match operation {
                    BarrelShifterOperation::RightShift => {
                        messages_for_next_next_blocks[0] = self.key.create_trivial(0);
                        messages_for_next_next_blocks[1] = self.key.create_trivial(0);
                        2..num_blocks
                    }
                    BarrelShifterOperation::LeftShift => {
                        messages_for_next_next_blocks[num_blocks - 1] = self.key.create_trivial(0);
                        messages_for_next_next_blocks[num_blocks - 2] = self.key.create_trivial(0);
                        0..num_blocks - 2
                    }
                    BarrelShifterOperation::LeftRotate | BarrelShifterOperation::RightRotate => {
                        0..num_blocks
                    }
                };
                messages_for_next_next_blocks[range]
                    .par_iter_mut()
                    .for_each(|block| {
                        self.key.unchecked_apply_lookup_table_bivariate_assign(
                            block,
                            first_block,
                            &message_for_next_next_block,
                        );
                    });
            });

            s.spawn(|_| {
                let num_bit_that_tells_shift_within_blocks = message_bits_per_block.ilog2();
                let num_bits_already_done = num_bit_that_tells_shift_within_blocks + 1;
                if u64::from(num_bits_already_done) == message_bits_per_block {
                    shift_bit_extractor.set_source_blocks(&amount.blocks[1..]);
                    shift_bit_extractor.prepare_next_batch();
                } else {
                    shift_bit_extractor.prepare_next_batch();
                    assert!(
                        shift_bit_extractor.current_buffer_len() > num_bits_already_done as usize
                    );
                    // Now remove bits that where used for the 'shift within blocks'
                    for _ in 0..num_bits_already_done {
                        let _ = shift_bit_extractor.next().unwrap();
                    }
                }
            });
        });

        // 0 should never be possible
        assert!(shift_bit_extractor.current_buffer_len() >= 1);

        match operation {
            BarrelShifterOperation::LeftShift | BarrelShifterOperation::LeftRotate => {
                messages_for_next_blocks.rotate_right(1);
                messages_for_next_next_blocks.rotate_right(2);
            }
            BarrelShifterOperation::RightShift | BarrelShifterOperation::RightRotate => {
                messages_for_next_blocks.rotate_left(1);
                messages_for_next_next_blocks.rotate_left(2);
            }
        }

        for (m0, (m1, m2)) in messages.iter_mut().zip(
            messages_for_next_blocks
                .iter()
                .zip(messages_for_next_next_blocks.iter()),
        ) {
            self.key.unchecked_add_assign(m0, m1);
            self.key.unchecked_add_assign(m0, m2);
        }

        let radix = T::from_blocks(messages);

        let num_bit_that_tells_shift_within_blocks = message_bits_per_block.ilog2();
        let num_bits_already_done = num_bit_that_tells_shift_within_blocks + 1;
        self.block_barrel_shifter_impl(
            &radix,
            &mut shift_bit_extractor,
            // We already did the first block rotation so we start at 1
            // And do + 1 as the range is exclusive
            1..max_num_bits_that_tell_shift - num_bits_already_done as usize + 1,
            // blocks are in little endian order which is the opposite
            // of how bits are textually represented
            operation.invert_direction(),
        )
    }

    /// This implements a "barrel shifter".
    ///
    /// This construct is what is used in hardware to
    /// implement left/right shift/rotate
    ///
    /// This requires:
    /// - ct to have clean carries
    /// - shift to have clean carries
    /// - the number of bits in the block to be >= 3
    ///
    /// Similarly to rust `wrapping_shl/shr` functions
    /// it removes any high-order bits of `shift`
    /// that would cause the shift to exceed the bitwidth of the type.
    ///
    /// **However**, when the total number of bits represented by the
    /// radix ciphertext is not a power of two (eg a ciphertext with 12 bits)
    /// then, it removes bit that are higher than the closest higher power of two.
    /// So for a 12 bits radix ciphertext, its closest higher power of two is 16,
    /// thus, any bit that are higher than log2(16) will be removed
    ///
    /// `ct` will be assigned the result, and it will be in a fresh state
    pub(super) fn bit_barrel_shifter<T>(
        &self,
        ct: &mut T,
        shift: &RadixCiphertext,
        operation: BarrelShifterOperation,
    ) where
        T: IntegerRadixCiphertext,
    {
        // What matters is the len of the ct to shift, not the `shift` len
        let num_blocks = ct.blocks().len();
        let message_bits_per_block = self.key.message_modulus.0.ilog2() as u64;
        let carry_bits_per_block = self.key.carry_modulus.0.ilog2() as u64;
        let total_nb_bits = message_bits_per_block * num_blocks as u64;

        assert!(
            (message_bits_per_block + carry_bits_per_block) >= 3,
            "Blocks must have at least 3 bits"
        );

        let (bits, shift_bits) = rayon::join(
            || {
                let mut bit_extractor =
                    BitExtractor::new(ct.blocks(), self, message_bits_per_block as usize);
                bit_extractor.extract_all_bits()
            },
            || {
                let mut max_num_bits_that_tell_shift = total_nb_bits.ilog2() as u64;
                // This effectively means, that if the block parameters
                // give a total_nb_bits that is not a power of two,
                // then the behaviour of shifting won't be the same
                // if shift >= total_nb_bits compared to when total_nb_bits
                // is a power of two, as will 'capture' more bits in `shift_bits`
                if !total_nb_bits.is_power_of_two() {
                    max_num_bits_that_tell_shift += 1;
                }

                // Extracts bits and put them in the bit index 2 (=> bit number 3)
                // so that it is already aligned to the correct position of the cmux input
                // and we reduce noise growth
                let mut bit_extractor = BitExtractor::with_final_offset(
                    &shift.blocks,
                    self,
                    message_bits_per_block as usize,
                    2,
                );
                bit_extractor.extract_n_bits(max_num_bits_that_tell_shift as usize)
            },
        );

        let mux_lut = self.key.generate_lookup_table(|x| {
            // x is expected to be x = 0bcba
            // where
            // - c is the control bit
            // - b the bit value returned if c is 1
            // - a the bit value returned if c is 0
            // (any bit above c is ignored)
            let x = x & 7;
            let control_bit = x >> 2;
            let previous_bit = (x & 2) >> 1;
            let current_bit = x & 1;

            if control_bit == 1 {
                previous_bit
            } else {
                current_bit
            }
        });

        let offset = match operation {
            BarrelShifterOperation::LeftShift | BarrelShifterOperation::LeftRotate => 0,
            BarrelShifterOperation::RightShift | BarrelShifterOperation::RightRotate => {
                total_nb_bits
            }
        };

        let is_right_shift = matches!(operation, BarrelShifterOperation::RightShift);
        let padding_bit = if T::IS_SIGNED && is_right_shift {
            // Do an "arithmetic shift" by padding with the sign bit
            bits.last().unwrap().clone()
        } else {
            self.key.create_trivial(0)
        };

        let mut input_bits_a = bits;
        let mut input_bits_b = input_bits_a.clone();
        // Buffer used to hold inputs for a bitwise cmux gate, simulated using a PBS
        let mut mux_inputs = input_bits_a.clone();

        for (d, shift_bit) in shift_bits.iter().enumerate() {
            for i in 0..total_nb_bits as usize {
                input_bits_b[i].clone_from(&input_bits_a[i]);
                self.key.create_trivial_assign(&mut mux_inputs[i], 0);
            }

            match operation {
                BarrelShifterOperation::LeftShift => {
                    input_bits_b.rotate_right(1 << d);
                    for bit_that_wrapped in &mut input_bits_b[..1 << d] {
                        bit_that_wrapped.clone_from(&padding_bit);
                    }
                }
                BarrelShifterOperation::RightShift => {
                    input_bits_b.rotate_left(1 << d);
                    let bits_that_wrapped = &mut input_bits_b[total_nb_bits as usize - (1 << d)..];
                    for bit_that_wrapped in bits_that_wrapped {
                        bit_that_wrapped.clone_from(&padding_bit);
                    }
                }
                BarrelShifterOperation::LeftRotate => {
                    input_bits_b.rotate_right(1 << d);
                }
                BarrelShifterOperation::RightRotate => {
                    input_bits_b.rotate_left(1 << d);
                }
            }

            input_bits_a
                .par_iter_mut()
                .zip_eq(mux_inputs.par_iter_mut())
                .enumerate()
                .for_each(|(i, (a, mux_gate_input))| {
                    let b = &input_bits_b[((i as u64 + offset) % total_nb_bits) as usize];

                    // pack bits into one block so that we have
                    // control_bit|b|a

                    self.key.unchecked_add_assign(mux_gate_input, b);
                    self.key.unchecked_scalar_mul_assign(mux_gate_input, 2);
                    self.key.unchecked_add_assign(mux_gate_input, &*a);
                    // The shift bit is already properly aligned/positioned
                    self.key.unchecked_add_assign(mux_gate_input, shift_bit);

                    // we have
                    //
                    // control_bit|b|a
                    self.key.apply_lookup_table_assign(mux_gate_input, &mux_lut);
                    (*a).clone_from(mux_gate_input);
                });
        }

        // rename for clarity
        let mut output_bits = input_bits_a;
        assert_eq!(
            output_bits.len(),
            message_bits_per_block as usize * num_blocks
        );
        // We have to reconstruct blocks from the individual bits
        output_bits
            .as_mut_slice()
            .par_chunks_exact_mut(message_bits_per_block as usize)
            .zip_eq(ct.blocks_mut().par_iter_mut())
            .for_each(|(grouped_bits, block)| {
                let (head, last) = grouped_bits.split_at_mut(message_bits_per_block as usize - 1);
                for bit in head.iter().rev() {
                    self.key.unchecked_scalar_mul_assign(&mut last[0], 2);
                    self.key.unchecked_add_assign(&mut last[0], bit);
                }
                // To give back a clean ciphertext
                self.key.message_extract_assign(&mut last[0]);
                std::mem::swap(block, &mut last[0]);
            });
    }
}
