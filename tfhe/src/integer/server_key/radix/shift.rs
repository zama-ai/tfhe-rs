use std::ops::Rem;

use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::CastFrom;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

impl ServerKey {
    /// Shifts the blocks to the right.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 16;
    /// let shift = 2;
    ///
    /// // Encrypt two messages:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.blockshift_right(&mut ct, shift);
    ///
    /// let div = cks.parameters().message_modulus().0.pow(shift as u32) as u64;
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(msg / div, clear);
    /// ```
    pub fn blockshift_right(&self, ctxt: &RadixCiphertext, shift: usize) -> RadixCiphertext {
        let mut result = self.create_trivial_zero_radix(ctxt.blocks.len());

        let limit = result.blocks.len() - shift;

        for (res_i, c_i) in result.blocks[..limit]
            .iter_mut()
            .zip(ctxt.blocks[shift..].iter())
        {
            *res_i = c_i.clone();
        }

        result
    }

    pub fn blockshift_right_assign(&self, ctxt: &mut RadixCiphertext, shift: usize) {
        *ctxt = self.blockshift_right(ctxt, shift);
    }

    /// Computes homomorphically a right shift.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 128u64;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_right_shift(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift<T>(&self, ct: &RadixCiphertext, shift: T) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(&mut result, shift);
        result
    }

    /// Computes homomorphically a right shift.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 18u64;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_right_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign<T>(&self, ct: &mut RadixCiphertext, shift: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // see parallel implementation for a bit more details

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
        let lut = self
            .key
            .generate_lookup_table_bivariate(|current_block, mut previous_block| {
                // left shift not to lose
                // bits when shifting right afterwards
                previous_block <<= num_bits_in_block;
                previous_block >>= shift_within_block;

                // The way of getting carry / message is reversed compared
                // to the usual way but its normal
                let message_of_current_block = current_block >> shift_within_block;
                let carry_of_previous_block = previous_block % message_modulus;

                message_of_current_block + carry_of_previous_block
            });
        let partial_blocks = ct.blocks[..num_blocks - rotations]
            .windows(2)
            .map(|blocks| {
                // We are right-shifting, which in our representation
                // means the previous_block (the one with the carry to be
                // progatated to the current_block) is the next block in the Vec
                let (current_block, previous_block) = (&blocks[0], &blocks[1]);
                self.key
                    .unchecked_apply_lookup_table_bivariate(current_block, previous_block, &lut)
            })
            .collect::<Vec<_>>();

        // We do this block separately as this one does not
        // need to get incoming bits from it neighbour
        self.key.scalar_right_shift_assign(
            &mut ct.blocks[num_blocks - rotations - 1],
            shift_within_block as u8,
        );

        // We started with num_blocks, discarded 'rotations' blocks
        // and did the last one separately
        let blocks_to_replace = &mut ct.blocks[..num_blocks - rotations - 1];
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
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 21u64;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_left_shift(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift<T>(
        &self,
        ct_left: &RadixCiphertext,
        shift: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct_left.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is assigned in the input ciphertext
    ///
    /// # Requirements
    ///
    /// - The blocks parameter's carry space have at least one more bit than message space
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 13u64;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_left_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_assign<T>(&self, ct: &mut RadixCiphertext, shift: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // see parallel implementation for a bit more details

        debug_assert!(ct.block_carries_are_empty());
        debug_assert!(self.key.carry_modulus.0 >= self.key.message_modulus.0 / 2);

        let shift = u64::cast_from(shift);
        if shift == 0 {
            return;
        }

        let num_bits_in_block = self.key.message_modulus.0.ilog2() as u64;
        let total_num_bits = num_bits_in_block * ct.blocks.len() as u64;
        let shift = shift % total_num_bits;

        let rotations = ((shift / num_bits_in_block) as usize).min(ct.blocks.len());
        let shift_within_block = shift % num_bits_in_block;

        // rotate right as the blocks are from LSB to MSB
        ct.blocks.rotate_right(rotations);
        for block in &mut ct.blocks[..rotations] {
            self.key.create_trivial_assign(block, 0)
        }

        if shift_within_block == 0 || rotations == ct.blocks.len() {
            return;
        }

        let lut = self
            .key
            .generate_lookup_table_bivariate(|current_block, previous_block| {
                let current_block = current_block << shift_within_block;
                let previous_block = previous_block << shift_within_block;

                let message_of_current_block = current_block % self.key.message_modulus.0 as u64;
                let carry_of_previous_block = previous_block / self.key.message_modulus.0 as u64;
                message_of_current_block + carry_of_previous_block
            });
        let partial_blocks = ct.blocks[rotations..]
            .windows(2)
            .map(|blocks| {
                // We are right-shifting,
                // so we get the bits from the next block in the vec
                let (previous_block, current_block) = (&blocks[0], &blocks[1]);
                self.key
                    .unchecked_apply_lookup_table_bivariate(current_block, previous_block, &lut)
            })
            .collect::<Vec<_>>();

        // We do this block separately as this one does not
        // need to get incoming bits from it neighbour
        let block = &mut ct.blocks[rotations];
        self.key
            .scalar_left_shift_assign(block, shift_within_block as u8);

        // We started with num_blocks, discarded 'rotations' blocks
        // and did the last one separately
        let blocks_to_replace = &mut ct.blocks[rotations + 1..];
        assert_eq!(partial_blocks.len(), blocks_to_replace.len());
        for (block, shifted_block) in izip!(blocks_to_replace, partial_blocks) {
            *block = shifted_block
        }
        debug_assert!(ct.block_carries_are_empty());
    }
}
