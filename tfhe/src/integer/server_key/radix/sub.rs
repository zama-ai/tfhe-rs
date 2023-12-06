use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix_parallel::sub::SignedOperation;
use crate::integer::server_key::CheckError;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::ciphertext::{Degree, MaxDegree, NoiseLevel};
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
    /// sks.is_sub_possible(&ctxt_1, &ctxt_2).unwrap();
    /// ```
    pub fn is_sub_possible<T>(&self, ctxt_left: &T, ctxt_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        let mut preceding_block_carry = Degree::new(0);
        let mut preceding_scaled_z = 0;
        let mut extracted_carry_noise_level = NoiseLevel::ZERO;
        for (left_block, right_block) in ctxt_left.blocks().iter().zip(ctxt_right.blocks().iter()) {
            // Assumes message_modulus and carry_modulus matches between pairs of block
            let msg_mod = left_block.message_modulus.0;
            let max_degree = MaxDegree::from_msg_carry_modulus(
                left_block.message_modulus,
                left_block.carry_modulus,
            );

            // z = ceil( degree / 2^p ) x 2^p
            let mut z = divide_ceil(right_block.degree.get(), msg_mod);
            z = z.wrapping_mul(msg_mod);
            // In the actual operation, preceding_scaled_z is added to the ciphertext
            // before doing lwe_ciphertext_opposite:
            // i.e the code does -(ciphertext + preceding_scaled_z) + z
            // here we do -ciphertext -preceding_scaled_z + z
            // which is easier to express degree
            let right_block_degree_after_negation = Degree::new(z - preceding_scaled_z);

            let degree_after_add = left_block.degree + right_block_degree_after_negation;

            // We want to be able to add the left block, the negated right block
            // and we also want to be able to add the carry from preceding block addition
            // to make sure carry propagation would be correct.
            max_degree.validate(degree_after_add + preceding_block_carry)?;

            self.key.max_noise_level.validate(
                left_block.noise_level() + right_block.noise_level() + extracted_carry_noise_level,
            )?;

            preceding_block_carry = Degree::new(degree_after_add.get() / msg_mod);
            preceding_scaled_z = z / msg_mod;
            extracted_carry_noise_level = NoiseLevel::NOMINAL;
        }
        Ok(())
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
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
        self.is_sub_possible(ctxt_left, ctxt_right)?;
        Ok(self.unchecked_sub(ctxt_left, ctxt_right))
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
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
    /// sks.checked_sub_assign(&mut ct1, &ct2).unwrap();
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1.wrapping_sub(msg2) as u64, clear);
    /// ```
    pub fn checked_sub_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_sub_possible(ct_left, ct_right)?;
        self.unchecked_sub_assign(ct_left, ct_right);
        Ok(())
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
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            self.full_propagate(ctxt_left);
            self.full_propagate(ctxt_right);
        }

        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

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
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            self.full_propagate(ctxt_left);
            self.full_propagate(ctxt_right);
        }

        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

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
    /// let decrypted_overflow = cks.decrypt_bool(&overflowed);
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn unsigned_overflowing_sub(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
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
    ) -> (RadixCiphertext, BooleanBlock) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );
        // Here we have to use manual unchecked_sub on shortint blocks
        // rather than calling integer's unchecked_sub as we need each subtraction
        // to be independent from other blocks. And we don't want to do subtraction by
        // adding negation
        let result = lhs
            .blocks
            .iter()
            .zip(rhs.blocks.iter())
            .map(|(lhs_block, rhs_block)| self.key.unchecked_sub(lhs_block, rhs_block))
            .collect::<Vec<_>>();
        let mut result = RadixCiphertext::from(result);
        let overflowed = self.unsigned_overflowing_propagate_subtraction_borrow(&mut result);
        (result, overflowed)
    }

    pub(crate) fn unchecked_signed_overflowing_add_or_sub(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
        signed_operation: SignedOperation,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let mut result = lhs.clone();

        let num_blocks = result.blocks.len();
        if num_blocks == 0 {
            return (result, self.create_trivial_boolean_block(false));
        }

        fn block_add_assign_returning_carry(
            sks: &ServerKey,
            lhs: &mut Ciphertext,
            rhs: &Ciphertext,
        ) -> Ciphertext {
            sks.key.unchecked_add_assign(lhs, rhs);
            let (carry, message) = rayon::join(
                || sks.key.carry_extract(lhs),
                || sks.key.message_extract(lhs),
            );

            *lhs = message;

            carry
        }

        // 2_2, 3_3, 4_4
        // If we have at least 2 bits and at least as much carries
        if self.key.message_modulus.0 >= 4 && self.key.carry_modulus.0 >= self.key.message_modulus.0
        {
            if signed_operation == SignedOperation::Subtraction {
                self.unchecked_sub_assign(&mut result, rhs);
            } else {
                self.unchecked_add_assign(&mut result, rhs);
            }

            let mut input_carry = self.key.create_trivial(0);

            // For the first block do the first step of overflow computation in parallel
            let (_, last_block_inner_propagation) = rayon::join(
                || {
                    input_carry =
                        block_add_assign_returning_carry(self, &mut result.blocks[0], &input_carry);
                },
                || {
                    self.generate_last_block_inner_propagation(
                        &lhs.blocks[num_blocks - 1],
                        &rhs.blocks[num_blocks - 1],
                        signed_operation,
                    )
                },
            );

            for block in result.blocks[1..num_blocks - 1].iter_mut() {
                input_carry = block_add_assign_returning_carry(self, block, &input_carry);
            }

            // Treat the last block separately to handle last step of overflow behavior
            let output_carry = block_add_assign_returning_carry(
                self,
                &mut result.blocks[num_blocks - 1],
                &input_carry,
            );
            let overflowed = self.resolve_signed_overflow(
                last_block_inner_propagation,
                &BooleanBlock::new_unchecked(input_carry),
                &BooleanBlock::new_unchecked(output_carry),
            );

            return (result, overflowed);
        }

        // 1_X parameters
        //
        // Same idea as other algorithms, however since we have 1 bit per block
        // we do not have to resolve any inner propagation but it adds one more
        // sequential PBS
        if self.key.message_modulus.0 == 2 {
            if signed_operation == SignedOperation::Subtraction {
                self.unchecked_sub_assign(&mut result, rhs);
            } else {
                self.unchecked_add_assign(&mut result, rhs);
            }

            let mut input_carry = self.key.create_trivial(0);
            for block in result.blocks[..num_blocks - 1].iter_mut() {
                input_carry = block_add_assign_returning_carry(self, block, &input_carry);
            }

            let output_carry = block_add_assign_returning_carry(
                self,
                &mut result.blocks[num_blocks - 1],
                &input_carry,
            );

            // Encode the rule
            // "Overflow occurred if the carry into the last bit is different than the carry out
            // of the last bit"
            let overflowed = self.key.not_equal(&output_carry, &input_carry);
            return (result, BooleanBlock::new_unchecked(overflowed));
        }

        panic!(
            "Invalid combo of message modulus ({}) and carry modulus ({}) \n\
            This function requires the message modulus >= 2 and carry modulus >= message_modulus \n\
            I.e. PARAM_MESSAGE_X_CARRY_Y where X >= 1 and Y >= X.",
            self.key.message_modulus.0, self.key.carry_modulus.0
        );
    }
    pub fn unchecked_signed_overflowing_sub(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        self.unchecked_signed_overflowing_add_or_sub(lhs, rhs, SignedOperation::Subtraction)
    }

    pub fn signed_overflowing_sub(
        &self,
        ctxt_left: &SignedRadixCiphertext,
        ctxt_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
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

        self.unchecked_signed_overflowing_sub(lhs, rhs)
    }
}
