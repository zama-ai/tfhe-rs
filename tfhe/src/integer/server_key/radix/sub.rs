use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::{RadixCiphertext, ServerKey};
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg_1 = 12;
    /// let msg_2 = 10;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.unchecked_sub(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub<T>(&self, ctxt_left: &T, ctxt_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);
        result
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg_1 = 128;
    /// let msg_2 = 99;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.unchecked_sub_assign(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub_assign<T>(&self, ctxt_left: &mut T, ctxt_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let neg = self.unchecked_neg(ctxt_right);
        self.unchecked_add_assign(ctxt_left, &neg);
    }

    /// Verifies if ct_right can be subtracted to ct_left.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg_1 = 182u64;
    /// let msg_2 = 120u64;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Check if we can perform a subtraction
    /// let res = sks.is_sub_possible(&ctxt_1, &ctxt_2);
    ///
    /// assert_eq!(true, res);
    /// ```
    pub fn is_sub_possible<T>(&self, ctxt_left: &T, ctxt_right: &T) -> bool
    where
        T: IntegerRadixCiphertext,
    {
        let mut preceding_block_carry = 0;
        let mut preceding_scaled_z = 0;
        for (left_block, right_block) in ctxt_left.blocks().iter().zip(ctxt_right.blocks().iter()) {
            // Assumes message_modulus and carry_modulus matches between pairs of block
            let msg_mod = left_block.message_modulus.0;
            let carry_mod = left_block.carry_modulus.0;
            let total_modulus = msg_mod * carry_mod;

            // z = ceil( degree / 2^p ) x 2^p
            let mut z = divide_ceil(right_block.degree.0, msg_mod);
            z = z.wrapping_mul(msg_mod);
            // In the actual operation, preceding_scaled_z is added to the ciphertext
            // before doing lwe_ciphertext_opposite:
            // i.e the code does -(ciphertext + preceding_scaled_z) + z
            // here we do -ciphertext -preceding_scaled_z + z
            // which is easier to express degree
            let right_block_degree_after_negation = z - preceding_scaled_z;

            let degree_after_add = left_block.degree.0 + right_block_degree_after_negation;

            // We want to be able to add the left block, the negated right block
            // and we also want to be able to add the carry from preceding block addition
            // to make sure carry propagation would be correct.
            if (degree_after_add + preceding_block_carry) >= total_modulus {
                return false;
            }

            preceding_block_carry = degree_after_add / msg_mod;
            preceding_scaled_z = z / msg_mod;
        }
        true
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
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
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg);
    /// let ctxt_2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.checked_sub(&ctxt_1, &ctxt_2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(0, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_sub<T>(&self, ctxt_left: &T, ctxt_right: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_sub_possible(ctxt_left, ctxt_right) {
            Ok(self.unchecked_sub(ctxt_left, ctxt_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 41u8;
    /// let msg2 = 101u8;
    ///
    /// let mut ct1 = cks.encrypt(msg1 as u64);
    /// let ct2 = cks.encrypt(msg2 as u64);
    ///
    /// // Compute homomorphically an addition:
    /// let res = sks.checked_sub_assign(&mut ct1, &ct2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1.wrapping_sub(msg2) as u64, clear);
    /// ```
    pub fn checked_sub_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_sub_possible(ct_left, ct_right) {
            self.unchecked_sub_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.smart_sub(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            self.full_propagate(ctxt_left);
            self.full_propagate(ctxt_right);
        }

        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);

        result
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.smart_sub_assign(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_assign<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            self.full_propagate(ctxt_left);
            self.full_propagate(ctxt_right);
        }

        self.unchecked_sub_assign(ctxt_left, ctxt_right);
    }

    /// Computes the subtraction and returns an indicator of overflow
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
    /// let msg_1 = 1u8;
    /// let msg_2 = 2u8;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction
    /// let (result, overflowed) = sks.unsigned_overflowing_sub(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let decrypted_result: u8 = cks.decrypt(&result);
    /// let decrypted_overflow = cks.decrypt_one_block(&overflowed) == 1;
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn unsigned_overflowing_sub(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> (RadixCiphertext, Ciphertext) {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ctxt_left.clone();
                self.full_propagate(&mut tmp_lhs);
                (&tmp_lhs, ctxt_right)
            }
            (false, false) => {
                tmp_lhs = ctxt_left.clone();
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate(&mut tmp_lhs),
                    || self.full_propagate(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_unsigned_overflowing_sub(lhs, rhs)
    }

    pub fn unchecked_unsigned_overflowing_sub(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> (RadixCiphertext, Ciphertext) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );
        let modulus = self.key.message_modulus.0 as u64;

        // If the block does not have a carry after the subtraction, it means it needs to
        // borrow from the next block
        let compute_borrow_lut = self
            .key
            .generate_lookup_table(|x| if x < modulus { 1 } else { 0 });

        let mut borrow = self.key.create_trivial(0);
        let mut new_blocks = Vec::with_capacity(lhs.blocks.len());
        for (lhs_b, rhs_b) in lhs.blocks.iter().zip(rhs.blocks.iter()) {
            let mut result_block = self.key.unchecked_sub(lhs_b, rhs_b);
            // Here unchecked_sub_assign does not give correct result, we don't want
            // the correcting term to be used
            // -> This is ok as the value returned by unchecked_sub is in range 1..(message_mod * 2)
            crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                &mut result_block.ct,
                &borrow.ct,
            );
            let (msg, new_borrow) = rayon::join(
                || self.key.message_extract(&result_block),
                || {
                    self.key
                        .apply_lookup_table(&result_block, &compute_borrow_lut)
                },
            );
            result_block = msg;
            borrow = new_borrow;
            new_blocks.push(result_block);
        }

        // borrow of last block indicates overflow
        let overflowed = borrow;
        (RadixCiphertext::from(new_blocks), overflowed)
    }
}
