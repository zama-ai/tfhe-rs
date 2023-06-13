use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::ServerKey;

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
    pub fn unchecked_sub(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> RadixCiphertext {
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
    pub fn unchecked_sub_assign(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) {
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
    pub fn is_sub_possible(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> bool {
        for (ct_left_i, ct_right_i) in ctxt_left.blocks.iter().zip(ctxt_right.blocks.iter()) {
            if !self.key.is_sub_possible(ct_left_i, ct_right_i) {
                return false;
            }
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
    pub fn checked_sub(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> Result<RadixCiphertext, CheckError> {
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
    pub fn checked_sub_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<(), CheckError> {
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
    pub fn smart_sub(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
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
    pub fn smart_sub_assign(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) {
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
}
