use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix_parallel::add::OutputCarry;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use rayon::prelude::*;

impl ServerKey {
    pub fn unsigned_overflowing_scalar_add_assign_parallelized<Scalar>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        self.unchecked_scalar_add_assign(lhs, scalar);
        let overflowed = self.unsigned_overflowing_propagate_addition_carry(lhs);

        let num_scalar_block =
            BlockDecomposer::with_early_stop_at_zero(scalar, self.key.message_modulus.0.ilog2())
                .count();

        if num_scalar_block > lhs.blocks.len() {
            // Scalar has more blocks so addition counts as overflowing
            BooleanBlock::new_unchecked(self.key.create_trivial(1))
        } else {
            overflowed
        }
    }

    pub fn unsigned_overflowing_scalar_add_parallelized<Scalar>(
        &self,
        lhs: &RadixCiphertext,
        scalar: Scalar,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        let overflowed =
            self.unsigned_overflowing_scalar_add_assign_parallelized(&mut result, scalar);
        (result, overflowed)
    }

    pub fn signed_overflowing_scalar_add_parallelized<Scalar>(
        &self,
        lhs: &SignedRadixCiphertext,
        scalar: Scalar,
    ) -> (SignedRadixCiphertext, BooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u64>,
    {
        let mut tmp_lhs;
        let lhs = if lhs.block_carries_are_empty() {
            lhs
        } else {
            tmp_lhs = lhs.clone();
            self.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        };

        // To keep the code simple we transform the scalar into a trivial
        // performances wise this won't have much impact as all the cost is
        // in the carry propagation
        let trivial: SignedRadixCiphertext = self.create_trivial_radix(scalar, lhs.blocks.len());
        let (result, overflowed) = self.signed_overflowing_add_parallelized(lhs, &trivial);

        let mut extra_scalar_block_iter =
            BlockDecomposer::new(scalar, self.key.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .skip(lhs.blocks.len());

        let extra_blocks_have_correct_value = if scalar < Scalar::ZERO {
            extra_scalar_block_iter.all(|block| block == (self.message_modulus().0 as u64 - 1))
        } else {
            extra_scalar_block_iter.all(|block| block == 0)
        };

        if extra_blocks_have_correct_value {
            (result, overflowed)
        } else {
            // Scalar has more blocks so addition counts as overflowing
            (
                result,
                BooleanBlock::new_unchecked(self.key.create_trivial(1)),
            )
        }
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_add_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        if self.is_scalar_add_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_add_possible(ct, scalar).unwrap();
        self.unchecked_scalar_add(ct, scalar)
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 129;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.smart_scalar_add_assign_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        if self.is_scalar_add_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_add_possible(ct, scalar).unwrap();
        self.unchecked_scalar_add_assign(ct, scalar);
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.scalar_add_parallelized(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.scalar_add_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 129;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.scalar_add_assign_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };

        if self.is_eligible_for_parallel_single_carry_propagation(ct)
            && self.carry_modulus().0 >= self.message_modulus().0
        {
            self.packed_scalar_add_assign_parallelized(ct, scalar);
        } else if self.is_eligible_for_parallel_single_carry_propagation(ct) {
            self.unchecked_scalar_add_assign(ct, scalar);
            let _carry = self.propagate_single_carry_parallelized_low_latency(ct.blocks_mut());
        } else {
            self.unchecked_scalar_add_assign(ct, scalar);
            self.full_propagate_parallelized(ct);
        }
    }

    /// Parallel scalar add usable when `carry_modulus >= message_modulus`
    ///
    /// This relies on hillis and steele propagation (so hillis-steele preconditions apply),
    /// and it uses the precondition `carry_modulus >= message_modulus` plus
    /// the fact that rhs is a clear value to pack the block,
    /// resulting in one less iteration of carry propagation.
    pub(crate) fn packed_scalar_add_assign_parallelized<T, Scalar>(
        &self,
        ct: &mut T,
        scalar: Scalar,
    ) where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        let mut packed_blocks = ct
            .blocks()
            .chunks(2)
            .map(|chunk| self.pack_block_chunk(chunk))
            .collect::<Vec<_>>();
        let packed_modulus = (self.message_modulus().0 * self.message_modulus().0) as u64;

        // Luts that generate the Generates/Propagates/None state for packed block
        // Each packed blocks has its own LUT as we embed the scalar value inside
        let gpn_luts = BlockDecomposer::new(scalar, packed_modulus.ilog2())
            .iter_as::<u8>()
            .enumerate()
            .take(packed_blocks.len())
            .map(|(i, packed_scalar_block)| {
                self.key.generate_lookup_table(|x| {
                    let r = x + u64::from(packed_scalar_block);
                    if r >= packed_modulus {
                        OutputCarry::Generated as u64
                    } else if r == packed_modulus - 1 {
                        if i == 0 {
                            // The first block won't receive a carry so its state
                            // cannot be Propagated
                            OutputCarry::None as u64
                        } else {
                            OutputCarry::Propagated as u64
                        }
                    } else {
                        OutputCarry::None as u64
                    }
                })
            })
            .collect::<Vec<_>>();

        // Luts that generate the block that corresponds to the high block of a packed chunk
        // in a state so that it is ready to accept the carry generated by the previous packed
        // block in other words, the carry that the low block in its packing would
        // receive
        let luts2 = BlockDecomposer::new(scalar, packed_modulus.ilog2())
            .iter_as::<u8>()
            .take(packed_blocks.len())
            .map(|packed_scalar_block| {
                self.key.generate_lookup_table(|x| {
                    let low_x = x % self.message_modulus().0 as u64;
                    let high_x = x / self.message_modulus().0 as u64;

                    let low_scalar =
                        u64::from(packed_scalar_block) % self.message_modulus().0 as u64;
                    let high_scalar =
                        u64::from(packed_scalar_block) / self.message_modulus().0 as u64;

                    let low_r = low_x + low_scalar;
                    // The result of high_x + high_scalar will be shifted by one bit
                    // so the bit at index 0 can accept the bit that encodes the propagation
                    // state of the low block, such that when we add the carry generated
                    // by the previous packed chunk we get the correct result of the high part
                    //
                    // That result is shifted by one bit, so the extract_message will need
                    // to be different
                    let v = if low_r >= self.message_modulus().0 as u64 {
                        2
                    } else if low_r == self.message_modulus().0 as u64 - 1 {
                        1
                    } else {
                        0
                    };

                    (((high_scalar + high_x) % self.message_modulus().0 as u64) << 1) + v
                })
            })
            .collect::<Vec<_>>();

        let mut inner_pack_propagation = packed_blocks.clone();
        packed_blocks
            .par_iter_mut()
            .chain(inner_pack_propagation.par_iter_mut())
            .zip(gpn_luts.par_iter().chain(luts2.par_iter()))
            .for_each(|(block, lut)| self.key.apply_lookup_table_assign(block, lut));
        let generates_or_propagates = packed_blocks; // Rename

        let (carries, _) =
            self.compute_carry_propagation_parallelized_low_latency(generates_or_propagates);

        ct.blocks_mut()
            .iter_mut()
            .step_by(2)
            .zip(
                BlockDecomposer::new(scalar, self.message_modulus().0.ilog2())
                    .iter_as::<u8>()
                    .step_by(2),
            )
            .for_each(|(block, scalar)| self.key.unchecked_scalar_add_assign(block, scalar));

        ct.blocks_mut()
            .iter_mut()
            .skip(1)
            .step_by(2)
            .zip(inner_pack_propagation)
            .for_each(|(ct_block, new_value)| *ct_block = new_value);

        // Finally add the carries and then, do the message extract
        ct.blocks_mut()
            .chunks_mut(2)
            .zip(carries.iter())
            .for_each(|(blocks, carry)| {
                self.key.unchecked_add_assign(&mut blocks[0], carry);
                self.key.unchecked_add_assign(&mut blocks[1], carry);
            });

        let message_extract_lut = self
            .key
            .generate_lookup_table(|x| x % self.message_modulus().0 as u64);
        let shift_message_extract_lut = self
            .key
            .generate_lookup_table(|x| (x >> 1) % self.message_modulus().0 as u64);
        ct.blocks_mut()
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, block)| {
                if i & 1 == 0 {
                    self.key
                        .apply_lookup_table_assign(block, &message_extract_lut)
                } else {
                    self.key
                        .apply_lookup_table_assign(block, &shift_message_extract_lut)
                }
            });
    }
}
