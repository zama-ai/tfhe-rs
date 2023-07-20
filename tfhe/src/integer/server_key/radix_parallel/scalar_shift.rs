use std::ops::Rem;

use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::CastFrom;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

use rayon::prelude::*;

impl ServerKey {
    //======================================================================
    //                Shift Right
    //======================================================================

    /// Computes homomorphically a right shift.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Requirements
    ///
    /// - The blocks parameter's carry space have at least one more bit than message space
    /// - The input ciphertext carry buffer is emtpy / clean
    ///
    /// # Output
    ///
    /// - The output's carries will be clean
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
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_parallelized<T>(
        &self,
        ct: &RadixCiphertext,
        shift: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a right shift.
    ///
    /// # Requirements
    ///
    /// - The blocks parameter's carry space have at at least (message_bits - 1)
    /// - The input ciphertext carry buffer is emtpy / clean
    ///
    /// # Output
    ///
    /// - The carry of the output blocks will be emtpy / clean
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
    /// let msg = 18;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_right_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        shift: T,
    ) where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // The general idea, is that we know by how much we want to shift
        // since `shift` is a clear value.
        //
        // So we can use that to implement shifting in two step
        // 1) shift blocks (implemented by using rotate + replace with
        //    trivial ciphertext block which 'wrapped around`
        // 2) shift within each block and 'propagate' block to the next one
        //
        debug_assert!(ct.block_carries_are_empty());
        debug_assert!(self.key.carry_modulus.0 >= self.key.message_modulus.0 / 2);

        let num_bits_in_block = self.key.message_modulus.0.ilog2() as u64;
        let total_num_bits = num_bits_in_block * ct.blocks.len() as u64;

        let shift = shift % T::cast_from(total_num_bits);
        let shift = u64::cast_from(shift);
        if shift == 0 {
            return;
        }

        let rotations = ((shift / num_bits_in_block) as usize).min(ct.blocks.len());
        let shift_within_block = shift % num_bits_in_block;
        let num_blocks = ct.blocks.len();

        // rotate left as the blocks are from LSB to MSB
        ct.blocks.rotate_left(rotations);
        for block in &mut ct.blocks[num_blocks - rotations..] {
            self.key.create_trivial_assign(block, 0)
        }

        if shift_within_block == 0 || rotations == ct.blocks.len() {
            return;
        }

        let message_modulus = self.key.message_modulus.0 as u64;

        // Since we require that carries are empty,
        // we can use the bivariate bps to shift and propagate in parallel at the same time
        // instead of first shifting then propagating
        //
        // The first block is done separately as it does not
        // need to recuperate the shifted bits from its next block,
        // and also that way is does not need a special case for when rotations == 0
        let create_blocks_using_bivariate_pbs = || {
            let lut = self
                .key
                .generate_lookup_table_bivariate(|current_block, mut next_block| {
                    // left shift so as not to lose
                    // bits when shifting right afterwards
                    next_block <<= num_bits_in_block;
                    next_block >>= shift_within_block;

                    // The way of gettint carry / message is reversed compared
                    // to the usual way but its normal:
                    // The message is in the upper bits, the carry in lower bits
                    let message_of_current_block = current_block >> shift_within_block;
                    let carry_of_previous_block = next_block % message_modulus;

                    message_of_current_block + carry_of_previous_block
                });
            let partial_blocks = ct.blocks[..num_blocks - rotations]
                .par_windows(2)
                .map(|blocks| {
                    // We are right-shifting,
                    // so we get the bits from the next block in the vec
                    let (current_block, next_block) = (&blocks[0], &blocks[1]);
                    self.key
                        .unchecked_apply_lookup_table_bivariate(current_block, next_block, &lut)
                })
                .collect::<Vec<_>>();
            partial_blocks
        };

        let shift_last_block = || {
            let block = &ct.blocks[num_blocks - rotations - 1];
            self.key.scalar_right_shift(block, shift_within_block as u8)
        };
        let (partial_blocks, last_shifted_block) =
            rayon::join(create_blocks_using_bivariate_pbs, shift_last_block);
        ct.blocks[num_blocks - rotations - 1] = last_shifted_block;

        // We started with num_blocks, discarded 'rotations' blocks
        // and did the last one separately
        let blocks_to_replace = &mut ct.blocks[..num_blocks - rotations - 1];
        assert_eq!(partial_blocks.len(), blocks_to_replace.len());
        for (block, shifted_block) in izip!(blocks_to_replace, partial_blocks) {
            *block = shifted_block
        }
        debug_assert!(ct.block_carries_are_empty());
    }

    /// Computes homomorphically a right shift.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.scalar_right_shift_parallelized(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn scalar_right_shift_parallelized<T>(
        &self,
        ct: &RadixCiphertext,
        shift: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct.clone();
        self.scalar_right_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a right shift.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 18;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.scalar_right_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn scalar_right_shift_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, shift: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_right_shift_assign_parallelized(ct, shift);
    }

    //======================================================================
    //                Shift Left
    //======================================================================

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Requirements
    ///
    /// - The blocks parameter's carry space have at least one more bit than message space
    /// - The input ciphertext carry buffer is emtpy / clean
    ///
    /// # Output
    ///
    /// - The output ciphertext carry buffers will be clean / empty
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
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a left shift:
    /// let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_parallelized<T>(
        &self,
        ct_left: &RadixCiphertext,
        shift: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct_left.clone();
        self.unchecked_scalar_left_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is assigned in the input ciphertext
    ///
    /// # Requirements
    ///
    /// - The blocks parameter's carry space have at at least (message_bits - 1)
    /// - The input ciphertext carry buffer is emtpy / clean
    ///
    /// # Output
    ///
    /// - The ct carry buffers will be clean / empty afterwards
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
    /// let msg = 13;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a left shift:
    /// sks.unchecked_scalar_left_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_assign_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        shift: T,
    ) where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // The general idea, is that we know by how much we want to shift
        // since `shift` is a clear value.
        //
        // So we can use that to implement shifting in two step
        // 1) shift blocks (implemented by using rotate + replace with
        //    trivial ciphertext block which 'wrapped around`
        // 2) shift within each block in propagate block to the next one

        debug_assert!(ct.block_carries_are_empty());
        debug_assert!(self.key.carry_modulus.0 >= self.key.message_modulus.0 / 2);

        let num_bits_in_block = self.key.message_modulus.0.ilog2() as u64;
        let total_num_bits = num_bits_in_block * ct.blocks.len() as u64;

        let shift = shift % T::cast_from(total_num_bits);
        let shift = u64::cast_from(shift);
        if shift == 0 {
            return;
        }

        let rotations = ((shift / num_bits_in_block) as usize).min(ct.blocks.len());
        let shift_within_block = shift % num_bits_in_block;

        // rotate right as the blocks are from LSB to MSB
        ct.blocks.rotate_right(rotations);
        // Every block below 'rotations' should be discarded
        for block in &mut ct.blocks[..rotations] {
            self.key.create_trivial_assign(block, 0)
        }

        if shift_within_block == 0 || rotations == ct.blocks.len() {
            return;
        }

        // Since we require that carries are empty,
        // we can use the bivariate bps to shift and propagate in parallel at the same time
        // instead of first shifting then propagating
        //
        // The first block is done separately as it does not
        // need to recuperate the shifted bits from its previous block,
        // and also that way is does not need a special case for when rotations == 0
        let create_blocks_using_bivariate_pbs = || {
            let lut = self
                .key
                .generate_lookup_table_bivariate(|previous_block, current_block| {
                    let current_block = current_block << shift_within_block;
                    let previous_block = previous_block << shift_within_block;

                    let message_of_current_block =
                        current_block % self.key.message_modulus.0 as u64;
                    let carry_of_previous_block =
                        previous_block / self.key.message_modulus.0 as u64;
                    message_of_current_block + carry_of_previous_block
                });
            let partial_blocks = ct.blocks[rotations..]
                .par_windows(2)
                .map(|blocks| {
                    let (previous_block, current_block) = (&blocks[0], &blocks[1]);
                    self.key.unchecked_apply_lookup_table_bivariate(
                        previous_block,
                        current_block,
                        &lut,
                    )
                })
                .collect::<Vec<_>>();
            partial_blocks
        };

        let shift_last_block = || {
            let mut block = ct.blocks[rotations].clone();
            self.key
                .scalar_left_shift_assign(&mut block, shift_within_block as u8);
            block
        };

        let (partial_blocks, block) =
            rayon::join(create_blocks_using_bivariate_pbs, shift_last_block);

        // We started with num_blocks, discarded 'rotations' blocks
        // and did the last one separately
        ct.blocks[rotations] = block;
        let blocks_to_replace = &mut ct.blocks[rotations + 1..];
        assert_eq!(partial_blocks.len(), blocks_to_replace.len());
        for (block, shifted_block) in izip!(blocks_to_replace, partial_blocks) {
            *block = shifted_block
        }
        debug_assert!(ct.block_carries_are_empty());
    }

    /// Computes homomorphically a left shift by a scalar.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a left shift:
    /// let ct_res = sks.scalar_left_shift_parallelized(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn scalar_left_shift_parallelized<T>(
        &self,
        ct_left: &RadixCiphertext,
        shift: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct_left.clone();
        self.scalar_left_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is assigned in the input ciphertext
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
    /// let msg = 13;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.scalar_left_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn scalar_left_shift_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, shift: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_left_shift_assign_parallelized(ct, shift);
    }
}
