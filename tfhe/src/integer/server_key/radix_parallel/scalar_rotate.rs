use std::ops::Rem;

use crate::core_crypto::prelude::CastFrom;
use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

use rayon::prelude::*;

impl ServerKey {
    //======================================================================
    //                Rotate Right
    //======================================================================

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// If necessary the carries of the input will be cleaned beforehand,
    /// but its value won't change, the result is returned in a new ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.smart_scalar_rotate_right_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn smart_scalar_rotate_right_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_rotate_right_parallelized(ct, n)
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
    ///
    /// If necessary carries will be cleaned beforehand
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.smart_scalar_rotate_right_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn smart_scalar_rotate_right_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, n: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_rotate_right_assign_parallelized(ct, n);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.scalar_rotate_right_parallelized(&ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn scalar_rotate_right_parallelized<T>(
        &self,
        ct_right: &RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct_right.clone();
        self.scalar_rotate_right_assign_parallelized(&mut result, n);
        result
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.scalar_rotate_right_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn scalar_rotate_right_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, n: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_rotate_right_assign_parallelized(ct, n);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn unchecked_scalar_rotate_right_parallelized<T>(
        &self,
        ct: &RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_rotate_right_assign_parallelized(&mut result, n);
        result
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the right by a specified amount,
    /// `n`, wrapping the truncated bits to the beginning of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.unchecked_scalar_rotate_right_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_right(n as u32) as u64, dec);
    /// ```
    pub fn unchecked_scalar_rotate_right_assign_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        n: T,
    ) where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // The general idea, is that we know by how much we want to
        // rotate since `n` is a clear value.
        //
        // So we can use that to implement rotating in two step
        // 1) rotate blocks
        // 2) shift within each block and `propagate' the next one
        debug_assert!(ct.block_carries_are_empty());
        debug_assert!(self.key.carry_modulus.0 >= self.key.message_modulus.0 / 2);

        let num_bits_in_message = self.key.message_modulus.0.ilog2() as u64;
        let total_num_bits = num_bits_in_message * ct.blocks.len() as u64;

        let n = n % T::cast_from(total_num_bits);
        let n = u64::cast_from(n);

        if n == 0 {
            return;
        }

        let rotations = (n / num_bits_in_message) as usize;
        let shift_within_block = n % num_bits_in_message;
        let num_blocks = ct.blocks.len();

        // rotate left as the blocks are from LSB to MSB
        ct.blocks.rotate_left(rotations);

        let message_modulus = self.key.message_modulus.0 as u64;
        if shift_within_block != 0 {
            let lut =
                self.key
                    .generate_lookup_table_bivariate(|receiver_block, mut giver_block| {
                        // left shift so as not to lose
                        // bits when shifting right afterwards
                        giver_block <<= num_bits_in_message;
                        giver_block >>= shift_within_block;

                        // The way of getting carry / message is reversed compared
                        // to the usual way but its normal:
                        // The message is in the upper bits, the carry in lower bits
                        let message_of_current_block = receiver_block >> shift_within_block;
                        let carry_of_previous_block = giver_block % message_modulus;

                        message_of_current_block + carry_of_previous_block
                    });
            let new_blocks = (0..num_blocks)
                .into_par_iter()
                .map(|index| {
                    // rotate_right means moving bits from MSB to LSB
                    // Since our blocks are from LSB to MSB, bits move from
                    // block `index + 1` to `index`
                    let bit_receiver_index = index;
                    let bit_giver_index = (index + 1) % num_blocks;

                    let bit_receiver_block = &ct.blocks[bit_receiver_index];
                    let bit_giver_block = &ct.blocks[bit_giver_index];
                    self.key.unchecked_apply_lookup_table_bivariate(
                        bit_receiver_block,
                        bit_giver_block,
                        &lut,
                    )
                })
                .collect::<Vec<_>>();
            ct.blocks = new_blocks;
        }

        debug_assert!(ct.block_carries_are_empty());
    }

    //======================================================================
    //                Rotate Left
    //======================================================================

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// If necessary the carries of the input will be cleaned beforehand,
    /// but its value won't change, the result is returned in a new ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.smart_scalar_rotate_left_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn smart_scalar_rotate_left_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_rotate_left_parallelized(ct, n)
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
    ///
    /// If necessary carries will be cleaned beforehand
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.smart_scalar_rotate_left_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn smart_scalar_rotate_left_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, n: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_rotate_left_assign_parallelized(ct, n);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.scalar_rotate_left_parallelized(&ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn scalar_rotate_left_parallelized<T>(
        &self,
        ct_left: &RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct_left.clone();
        self.scalar_rotate_left_assign_parallelized(&mut result, n);
        result
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.scalar_rotate_left_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn scalar_rotate_left_assign_parallelized<T>(&self, ct: &mut RadixCiphertext, n: T)
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        }

        self.unchecked_scalar_rotate_left_assign_parallelized(ct, n);
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let ct = cks.encrypt(msg as u64);
    ///
    /// let ct_res = sks.unchecked_scalar_rotate_left_parallelized(&ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn unchecked_scalar_rotate_left_parallelized<T>(
        &self,
        ct: &RadixCiphertext,
        n: T,
    ) -> RadixCiphertext
    where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_rotate_left_assign_parallelized(&mut result, n);
        result
    }

    /// Computes homomorphically a rotation of bits.
    ///
    /// Shifts the bits to the left by a specified amount,
    /// `n`, wrapping the truncated bits to the end of the resulting integer.
    ///
    /// The result is assigned to the input ciphertext
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
    /// let msg = 128u8;
    /// let n = 2;
    ///
    /// let mut ct = cks.encrypt(msg as u64);
    ///
    /// sks.unchecked_scalar_rotate_left_assign_parallelized(&mut ct, n);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg.rotate_left(n as u32) as u64, dec);
    /// ```
    pub fn unchecked_scalar_rotate_left_assign_parallelized<T>(
        &self,
        ct: &mut RadixCiphertext,
        n: T,
    ) where
        T: Rem<T, Output = T> + CastFrom<u64>,
        u64: CastFrom<T>,
    {
        // The general idea, is that we know by how much we want to
        // rotate since `n` is a clear value.
        //
        // So we can use that to implement rotating in two step
        // 1) rotate blocks
        // 2) shift within each block and 'propagate' to the next one
        debug_assert!(ct.block_carries_are_empty());
        debug_assert!(self.key.carry_modulus.0 >= self.key.message_modulus.0 / 2);

        let num_bits_in_message = self.key.message_modulus.0.ilog2() as u64;
        let total_num_bits = num_bits_in_message * ct.blocks.len() as u64;

        let n = u64::cast_from(n);
        let n = n % total_num_bits;

        if n == 0 {
            return;
        }

        let rotations = (n / num_bits_in_message) as usize;
        let shift_within_block = n % num_bits_in_message;
        let num_blocks = ct.blocks.len();

        // rotate right as the blocks are from LSB to MSB
        ct.blocks.rotate_right(rotations);

        if shift_within_block != 0 {
            let lut = self
                .key
                .generate_lookup_table_bivariate(|receiver_block, giver_block| {
                    let receiver_block = receiver_block << shift_within_block;
                    let giver_block = giver_block << shift_within_block;

                    let message_of_receiver_block =
                        receiver_block % self.key.message_modulus.0 as u64;
                    let carry_of_giver_block = giver_block / self.key.message_modulus.0 as u64;
                    message_of_receiver_block + carry_of_giver_block
                });
            let new_blocks = (0..num_blocks)
                .into_par_iter()
                .map(|index| {
                    // rotate_left means moving bits from LSB to MSB
                    // Since our blocs are from LSB to MSB, bits move from
                    // block `index - 1` to `index`
                    let bit_receiver_index = index;
                    let bit_giver_index = if index == 0 {
                        num_blocks - 1
                    } else {
                        index - 1
                    };

                    let bit_receiver_block = &ct.blocks[bit_receiver_index];
                    let bit_giver_block = &ct.blocks[bit_giver_index];
                    self.key.unchecked_apply_lookup_table_bivariate(
                        bit_receiver_block,
                        bit_giver_block,
                        &lut,
                    )
                })
                .collect::<Vec<_>>();
            ct.blocks = new_blocks;
        }

        debug_assert!(ct.block_carries_are_empty());
    }
}
