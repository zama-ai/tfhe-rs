use crate::core_crypto::prelude::{Cleartext, SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::radix::scalar_sub::TwosComplementNegation;
use crate::integer::{BooleanBlock, CheckError, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::{Ciphertext, PaddingBit};
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_sub_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn smart_scalar_sub_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_sub_possible(ct, scalar).unwrap();
        self.unchecked_scalar_sub(ct, scalar)
    }

    pub fn smart_scalar_sub_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_sub_possible(ct, scalar).unwrap();
        self.unchecked_scalar_sub_assign(ct, scalar);
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.scalar_sub_parallelized(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn scalar_sub_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.scalar_sub_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_sub_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        if Scalar::ZERO == scalar {
            return;
        }

        self.scalar_add_assign_parallelized(ct, scalar.twos_complement_negation());
    }

    pub fn unchecked_left_scalar_sub<Scalar, T>(&self, scalar: Scalar, rhs: &T) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        // a - b <=> a + (-b)
        let mut neg_rhs = self.unchecked_neg(rhs);
        self.unchecked_scalar_add_assign(&mut neg_rhs, scalar);
        neg_rhs
    }

    pub fn is_left_scalar_sub_possible<Scalar, T>(
        &self,
        scalar: Scalar,
        rhs: &T,
    ) -> Result<(), CheckError>
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        // We do scalar - ct by doing scalar + (-ct)
        // So we first have to check `-ct` is possible
        // then that adding scalar to it is possible
        self.is_neg_possible(rhs)?;
        let neg_degree_iter =
            NegatedDegreeIter::new(rhs.blocks().iter().map(|b| (b.degree, b.message_modulus)));
        let block_metadata_iter = rhs
            .blocks()
            .iter()
            .zip(neg_degree_iter)
            .map(|(block, neg_degree)| (neg_degree, block.message_modulus, block.carry_modulus));

        self.is_scalar_add_possible_impl(block_metadata_iter, scalar)
    }

    pub fn smart_left_scalar_sub_parallelized<Scalar, T>(&self, scalar: Scalar, rhs: &mut T) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        if self.is_neg_possible(rhs).is_err() {
            self.full_propagate_parallelized(rhs);
            self.unchecked_left_scalar_sub(scalar, rhs)
        } else {
            // a - b <=> a + (-b)
            let mut neg_rhs = self.unchecked_neg(rhs);
            if self.is_scalar_add_possible(&neg_rhs, scalar).is_err() {
                // since adding scalar does not increase the nose, only the
                // degree can be problematic
                self.full_propagate_parallelized(&mut neg_rhs);
            }
            self.unchecked_scalar_add_assign(&mut neg_rhs, scalar);
            neg_rhs
        }
    }

    pub fn left_scalar_sub_parallelized<Scalar, T>(&self, scalar: Scalar, rhs: &T) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        if rhs.block_carries_are_empty() {
            // a - b <=> a + (-b) <=> a + (!b + 1) <=> !b + a + 1
            let mut flipped_ct = self.bitnot(rhs);
            let scalar_blocks = BlockDecomposer::with_block_count(
                scalar,
                self.message_modulus().0.ilog2(),
                rhs.blocks().len(),
            )
            .iter_as::<u8>()
            .collect();
            let (input_carry, compute_overflow) = (true, false);
            self.add_assign_scalar_blocks_parallelized(
                &mut flipped_ct,
                scalar_blocks,
                input_carry,
                compute_overflow,
            );
            flipped_ct
        } else {
            // We could clone rhs and full_propagate, then do the same thing as when the
            // rhs's carries are clean. This would cost 2 full_propagate, but the second one
            // would be less expensive because it happens in a scalar_add.
            //
            // However, we chose to all the smart version on the cloned_rhs, as maybe the carries
            // are not so bad that the smart version will be able to avoid the first full_prop
            let mut tmp_rhs = rhs.clone();
            let mut res = self.smart_left_scalar_sub_parallelized(scalar, &mut tmp_rhs);
            self.full_propagate_parallelized(&mut res);
            res
        }
    }

    pub fn unsigned_overflowing_scalar_sub_assign_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: T,
    ) -> BooleanBlock
    where
        T: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = T>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        if self.is_eligible_for_parallel_single_carry_propagation(lhs.blocks.len()) {
            self.unsigned_overflowing_scalar_sub_assign_parallelized_at_least_4_bits(lhs, scalar)
        } else {
            self.unsigned_overflowing_scalar_sub_assign_parallelized_sequential(lhs, scalar)
        }
    }

    fn unsigned_overflowing_scalar_sub_assign_parallelized_sequential<Scalar>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        assert!(!lhs.blocks.is_empty(), "lhs cannot be empty");

        let scalar_blocks = BlockDecomposer::new(scalar, self.message_modulus().0.ilog2())
            .iter_as::<u8>()
            .take(lhs.blocks.len())
            .collect::<Vec<_>>();

        // If the block does not have a carry after the subtraction, it means it needs to
        // borrow from the next block
        let compute_borrow_lut =
            self.key
                .generate_lookup_table(|x| if x < self.message_modulus().0 { 1 } else { 0 });

        let mut borrow = self.key.create_trivial(0);
        let encoding = self.key.encoding(PaddingBit::Yes);
        for (lhs_b, scalar_b) in lhs.blocks.iter_mut().zip(scalar_blocks.iter().copied()) {
            // Here we use core_crypto instead of shortint scalar_sub_assign
            // because we need a true subtraction, not an addition of the inverse
            crate::core_crypto::algorithms::lwe_ciphertext_plaintext_sub_assign(
                &mut lhs_b.ct,
                encoding.encode(Cleartext(u64::from(scalar_b))),
            );
            crate::core_crypto::algorithms::lwe_ciphertext_plaintext_add_assign(
                &mut lhs_b.ct,
                encoding.encode(Cleartext(self.message_modulus().0)),
            );
            lhs_b.degree = crate::shortint::ciphertext::Degree::new(
                lhs_b.degree.get() + (self.message_modulus().0 - u64::from(scalar_b)),
            );
            // And here, it's because shortint sub_assign adds a correcting term,
            // which we do not want here
            crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(&mut lhs_b.ct, &borrow.ct);
            lhs_b.set_noise_level(
                lhs_b.noise_level() + borrow.noise_level(),
                self.key.max_noise_level,
            );

            borrow.clone_from(lhs_b);

            rayon::join(
                || self.key.message_extract_assign(lhs_b),
                || {
                    self.key
                        .apply_lookup_table_assign(&mut borrow, &compute_borrow_lut)
                },
            );
        }

        if BlockDecomposer::new(scalar, self.message_modulus().0.ilog2())
            .iter_as::<u8>()
            .skip(lhs.blocks.len())
            .any(|scalar_block| scalar_block != 0)
        {
            // The value we subtracted is bigger than what the ciphertext
            // can represent, so its a trivial overflow
            self.create_trivial_boolean_block(true)
        } else {
            // borrow of last block indicates overflow
            BooleanBlock::new_unchecked(borrow)
        }
    }

    fn unsigned_overflowing_scalar_sub_assign_parallelized_at_least_4_bits<Scalar>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        let packed_modulus = self.message_modulus().0 * self.message_modulus().0;

        let packed_blocks = lhs
            .blocks
            .chunks(2)
            .map(|chunk| self.pack_block_chunk(chunk))
            .collect::<Vec<_>>();

        let packed_scalar_blocks = BlockDecomposer::new(scalar, packed_modulus.ilog2())
            .iter_as::<u8>()
            .take(packed_blocks.len())
            .collect::<Vec<_>>();

        let num_blocks = lhs.blocks.len();
        // When the number of blocks is not even, the last packed block's
        // carry will be empty, this is an important detail in a few places
        // (like overflow detection)
        let num_block_is_even = (num_blocks & 1) == 0;

        let ((grouping_size, propagation_blocks, shifted_partial_result), mut overflow_block) =
            rayon::join(
                || {
                    self.scalar_compute_shifted_blocks_and_borrow_states(
                        &packed_blocks,
                        &packed_scalar_blocks,
                        num_block_is_even,
                        packed_modulus,
                    )
                },
                || {
                    let modulus = if num_block_is_even {
                        packed_modulus
                    } else {
                        self.message_modulus().0
                    };
                    let last_scalar_block =
                        u64::from(packed_scalar_blocks.last().copied().unwrap());
                    let lut = self.key.generate_lookup_table(|last_packed_block| {
                        let value = last_packed_block
                            .wrapping_sub(last_scalar_block)
                            .wrapping_add(modulus);
                        #[allow(clippy::comparison_chain)]
                        if value < modulus {
                            2 << 1 // Borrows
                        } else if value == modulus {
                            1 << 1 // Propagate
                        } else {
                            0 // None
                        }
                    });
                    let last_packed_block = packed_blocks.last().unwrap();
                    self.key.apply_lookup_table(last_packed_block, &lut)
                },
            );

        let (mut prepared_blocks, resolved_borrows) = {
            let (propagation_simulators, resolved_borrows) = self
                .compute_propagation_simulators_and_groups_carries(
                    grouping_size,
                    &propagation_blocks,
                );

            let mut prepared_blocks = shifted_partial_result;
            assert_eq!(
                prepared_blocks.len(),
                (propagation_simulators.len() * 2) - usize::from(!num_block_is_even)
            );
            prepared_blocks
                .chunks_mut(2)
                .zip(propagation_simulators.iter())
                .for_each(|(chunk_of_two, simulator)| {
                    // simulator may have either of these value
                    // '2' if the block is borrowed from
                    // '1' if the block will be borrowed from if the group it belongs to receive a
                    //     borrow
                    // '0' if the block will absorb any potential borrow
                    //
                    // What we do is we subtract this value from the block, as its a borrow, not a
                    // carry, and we add one, this means:
                    //
                    // '- (2 + 1) ==  -1' We remove one if the block was meant to receive a borrow
                    // '- (1 + 1) ==  -0' The block won't change, which means that when subtracting
                    // the borrow (value: 1 or 0) that the group receives, its correctly applied
                    // i.e the propagation simulation will be correctly done
                    // '- (0 + 1) ==  +1' we add one, meaning that if the block receives a borrow,
                    // we would remove one from the block, which would be absorbed by the 1 we just
                    // added
                    for block in chunk_of_two.iter_mut() {
                        crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                            &mut block.ct,
                            &simulator.ct,
                        );
                        block.set_noise_level(
                            block.noise_level() + simulator.noise_level(),
                            self.key.max_noise_level,
                        );
                        self.key.unchecked_scalar_add_assign(block, 1);
                    }
                });

            self.key
                .unchecked_add_assign(&mut overflow_block, propagation_simulators.last().unwrap());

            (prepared_blocks, resolved_borrows)
        };

        rayon::join(
            || {
                let extract_message_low_block_mut = self
                    .key
                    .generate_lookup_table(|block| (block >> 1) % self.message_modulus().0);
                let extract_message_high_block_mut = self
                    .key
                    .generate_lookup_table(|block| (block >> 2) % self.message_modulus().0);

                prepared_blocks
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, block)| {
                        let grouping_index = i / (grouping_size * 2);
                        let borrow = &resolved_borrows[grouping_index];
                        crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                            &mut block.ct,
                            &borrow.ct,
                        );
                        block.set_noise_level(
                            block.noise_level() + borrow.noise_level(),
                            self.key.max_noise_level,
                        );

                        let lut = if i % 2 == 0 {
                            &extract_message_low_block_mut
                        } else {
                            &extract_message_high_block_mut
                        };
                        self.key.apply_lookup_table_assign(block, lut);
                    });
            },
            || {
                let borrow_flag_lut = self.key.generate_lookup_table(|block| (block >> 2) & 1);
                self.key.unchecked_add_assign(
                    &mut overflow_block,
                    &resolved_borrows[resolved_borrows.len() - 1],
                );
                self.key
                    .apply_lookup_table_assign(&mut overflow_block, &borrow_flag_lut);
            },
        );

        for (out, b) in lhs.blocks.iter_mut().zip(prepared_blocks.iter_mut()) {
            std::mem::swap(out, b);
        }

        if BlockDecomposer::new(scalar, packed_modulus.ilog2())
            .iter_as::<u8>()
            .skip(packed_blocks.len())
            .any(|scalar_block| scalar_block != 0)
        {
            // The value we subtracted is bigger than what the ciphertext
            // can represent, so its a trivial overflow
            self.create_trivial_boolean_block(true)
        } else {
            BooleanBlock::new_unchecked(overflow_block)
        }
    }

    #[allow(clippy::comparison_chain)]
    fn scalar_compute_shifted_blocks_and_borrow_states(
        &self,
        packed_blocks: &[Ciphertext],
        packed_scalar_blocks: &[u8],
        num_block_is_even: bool,
        packed_modulus: u64,
    ) -> (usize, Vec<Ciphertext>, Vec<Ciphertext>) {
        let num_packing = packed_blocks.len();

        let num_bits_in_block = packed_modulus.ilog2();
        // Just in case we compare with max noise level, but it should always be num_bits_in_blocks
        // with the parameters we provide
        let grouping_size =
            (num_bits_in_block as usize).min(self.key.max_noise_level.get() as usize);

        // In this, we store lookup tables to be used on each 'packing'.
        // These LUTs will generate an output that tells whether the packing
        // generates a borrow, propagates, or does nothing
        //
        // The LUT for the first packing is not the same as other packing,
        // consequently LUTs for other packing in the first _grouping_ are
        // not the same as LUTs for other _groupings_.
        let packed_block_state_luts = {
            let mut luts = Vec::with_capacity(grouping_size);
            // We know the first packing is not going to receive any borrow
            // so, we use that to our advantage.
            luts.push(self.key.generate_lookup_table(|first_block| {
                let result = first_block
                    .wrapping_sub(u64::from(packed_scalar_blocks[0]))
                    .wrapping_add(packed_modulus);
                if result < packed_modulus {
                    1 // Borrows
                } else {
                    0 // Nothing
                }
            }));

            // LUTs for other packing in the _first grouping_
            for (index_in_grouping, packed_scalar_block) in packed_scalar_blocks
                .get(1..grouping_size.min(packed_scalar_blocks.len()))
                .unwrap_or(&[])
                .iter()
                .copied()
                .enumerate()
            {
                luts.push(
                    // As the first block in the first grouping is not going to be in propagate
                    // state, we also use that for other blocks in the grouping
                    // in order to save a bit, which is going to be important
                    // later
                    self.key.generate_lookup_table(|packed_block| {
                        let result = packed_block
                            .wrapping_sub(u64::from(packed_scalar_block))
                            .wrapping_add(packed_modulus);
                        let state = if result < packed_modulus {
                            2 // Borrows
                        } else if result == packed_modulus {
                            1 // Propagate
                        } else {
                            0 // Nothing
                        };

                        state << index_in_grouping
                    }),
                );
            }

            for (i, packed_scalar_block) in packed_scalar_blocks
                .get(grouping_size..)
                .unwrap_or(&[])
                .iter()
                .copied()
                .enumerate()
            {
                let index_in_grouping = i % grouping_size;
                luts.push(self.key.generate_lookup_table(|packed_block| {
                    let result = packed_block
                        .wrapping_sub(u64::from(packed_scalar_block))
                        .wrapping_add(packed_modulus);
                    let state = if result < packed_modulus {
                        2 // Borrows
                    } else if result == packed_modulus {
                        1 // Propagate
                    } else {
                        0 // Nothing
                    };

                    state << index_in_grouping
                }));
            }

            assert_eq!(luts.len(), packed_blocks.len());

            luts
        };

        // In this we store lookup tables that prepare the `low` and `high` block from a
        // _packing_ to be in a state were they are ready to receive `propagation simulator`
        // for previous packing in the same grouping they belong.
        let block_preparator_luts = {
            let message_modulus = self.message_modulus().0;
            let mut luts = Vec::with_capacity(packed_blocks.len());
            for (i, packed_scalar_block) in packed_scalar_blocks.iter().copied().enumerate() {
                let packed_scalar_block = u64::from(packed_scalar_block);

                // LUT to prepare the low block
                luts.push(self.key.generate_lookup_table(|packed_block| {
                    let result = packed_block.wrapping_sub(packed_scalar_block) % message_modulus;

                    // Shift by one as this will receive the carry of the group directly
                    if result == 0 {
                        // See high block for why this exists
                        let overflow_stopper = message_modulus;
                        (result + overflow_stopper) << 1
                    } else {
                        result << 1
                    }
                }));

                if i == num_packing - 1 && !num_block_is_even {
                    // The number of non-packed block is odd, so last packing does not have
                    // a high block
                    continue;
                }

                // LUT to prepare the high block
                luts.push(self.key.generate_lookup_table(|packed_block| {
                    let high_block = packed_block / self.message_modulus().0;
                    let high_scalar_block = packed_scalar_block / self.message_modulus().0;
                    let low_block = packed_block % self.message_modulus().0;
                    let low_scalar_block = packed_scalar_block % self.message_modulus().0;

                    let low_block_result = low_block
                        .wrapping_sub(low_scalar_block)
                        .wrapping_add(message_modulus);

                    let low_block_state = if low_block_result < self.message_modulus().0 {
                        2 // Borrows
                    } else if low_block_result == self.message_modulus().0 {
                        1 // Propagate
                    } else {
                        0 // Neither
                    };

                    let mut high_block_result =
                        high_block.wrapping_sub(high_scalar_block) % self.message_modulus().0;
                    high_block_result <<= 2;

                    // Same idea as in the non scalar version
                    // low_block_state == 2 => - (2 << 1) + 2 == -4 + 2 = -2 // directly borrow
                    // low_block_state == 1 => - (1 << 1) + 2 == -2 + 2 = +0 // if a borrow comes
                    // later is will be propagated
                    // low_block_state == 0 => - (0 << 1) + 2 == -0 + 2 = +2 // put a borrow
                    // absober
                    let value = high_block_result
                        .wrapping_sub(low_block_state << 1)
                        .wrapping_add(2)
                        % packed_modulus;
                    if value == 0 {
                        // If the value is 0, then if a borrow is subtracted the result will
                        // overflow and overwrite the padding bit, meaning
                        // subsequent cleaning lut will be incorrect. So we
                        // add a bit that will absorb the potential overflow.
                        //
                        // Note that this bit may be the padding bit itself, and in that case its
                        // still fine even if no borrow is actually subtracted as the cleaning lut
                        // would return 0, and since padding bit is set we would get -0, which is
                        // still 0.
                        let overflow_stopper = message_modulus << 2;
                        overflow_stopper | value
                    } else {
                        value
                    }
                }));
            }

            assert_eq!(
                luts.len(),
                (packed_blocks.len() * 2) - usize::from(!num_block_is_even)
            );

            luts
        };

        let (propagation_blocks, shifted_partial_result) = rayon::join(
            || {
                // we dont care about last block carry
                packed_blocks[0..packed_blocks.len() - 1]
                    .par_iter()
                    .zip(packed_block_state_luts.par_iter())
                    .map(|(packed_block, lut)| self.key.apply_lookup_table(packed_block, lut))
                    .collect::<Vec<_>>()
            },
            || {
                let mut blocks = Vec::with_capacity(packed_blocks.len() * 2);
                for block in packed_blocks[..packed_blocks.len().saturating_sub(1)].iter() {
                    blocks.push(block.clone());
                    blocks.push(block.clone());
                }
                if let Some(last_packing) = packed_blocks.last() {
                    blocks.push(last_packing.clone());
                    if num_block_is_even {
                        // The number of non-packed block is even, so each packing
                        // as low and high block
                        blocks.push(last_packing.clone());
                    }
                }

                assert_eq!(blocks.len(), block_preparator_luts.len());

                blocks
                    .par_iter_mut()
                    .zip(block_preparator_luts.par_iter())
                    .for_each(|(block, lut)| {
                        self.key.apply_lookup_table_assign(block, lut);
                    });
                blocks
            },
        );

        (grouping_size, propagation_blocks, shifted_partial_result)
    }

    pub fn unsigned_overflowing_scalar_sub_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        scalar: T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = T>,
    {
        let mut result = lhs.clone();
        let overflow =
            self.unsigned_overflowing_scalar_sub_assign_parallelized(&mut result, scalar);
        (result, overflow)
    }

    pub fn signed_overflowing_scalar_sub_assign_parallelized<Scalar>(
        &self,
        lhs: &mut SignedRadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: SignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        // The trivial overflow check has to be done on the scalar not its bit flipped version
        let mut decomposer = BlockDecomposer::new(scalar, self.message_modulus().0.ilog2())
            .iter_as::<u8>()
            .skip(lhs.blocks.len());

        let trivially_overflowed = if scalar < Scalar::ZERO {
            decomposer.any(|v| v != (self.message_modulus().0 - 1) as u8)
        } else {
            decomposer.any(|v| v != 0)
        };

        const INPUT_CARRY: bool = true;
        let flipped_scalar = !scalar;
        let decomposed_flipped_scalar = BlockDecomposer::with_block_count(
            flipped_scalar,
            self.message_modulus().0.ilog2(),
            lhs.blocks.len(),
        )
        .iter_as::<u8>()
        .collect::<Vec<_>>();
        let maybe_overflow = self.add_assign_scalar_blocks_parallelized(
            lhs,
            decomposed_flipped_scalar,
            INPUT_CARRY,
            !trivially_overflowed,
        );

        if trivially_overflowed {
            self.create_trivial_boolean_block(true)
        } else {
            maybe_overflow.expect("overflow computation was requested")
        }
    }

    pub fn signed_overflowing_scalar_sub_parallelized<Scalar>(
        &self,
        lhs: &SignedRadixCiphertext,
        scalar: Scalar,
    ) -> (SignedRadixCiphertext, BooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        let mut result = lhs.clone();
        let overflow = self.signed_overflowing_scalar_sub_assign_parallelized(&mut result, scalar);
        (result, overflow)
    }
}
