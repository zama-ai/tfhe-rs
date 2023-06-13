use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::CheckError;
use crate::shortint::CheckError::CarryFull;

impl ServerKey {
    /// Computes homomorphically bitand between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let ct_res = sks.unchecked_bitand(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn unchecked_bitand(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitand_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter_mut().zip(ct_right.blocks.iter()) {
            self.key.unchecked_bitand_assign(ct_left_i, ct_right_i);
        }
    }

    /// Verifies if a bivariate functional pbs can be applied on ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 46u64;
    /// let msg2 = 87u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let res = sks.is_functional_bivariate_pbs_possible(&ct1, &ct2);
    ///
    /// assert_eq!(true, res);
    /// ```
    pub fn is_functional_bivariate_pbs_possible(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> bool {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter().zip(ct_right.blocks.iter()) {
            if !self
                .key
                .is_functional_bivariate_pbs_possible(ct_left_i, ct_right_i)
            {
                return false;
            }
        }
        true
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.checked_bitand(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 & msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitand(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<RadixCiphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_bitand(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let res = sks.checked_bitand_assign(&mut ct1, &ct2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 & msg2, clear);
    /// ```
    pub fn checked_bitand_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitand_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitand(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 & msg2);
    /// ```
    pub fn smart_bitand(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitand(ct_left, ct_right)
    }

    pub fn smart_bitand_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitand_assign(ct_left, ct_right);
    }

    /// Computes homomorphically bitor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 200;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise or:
    /// let ct_res = sks.unchecked_bitor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn unchecked_bitor(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter_mut().zip(ct_right.blocks.iter()) {
            self.key.unchecked_bitor_assign(ct_left_i, ct_right_i);
        }
    }

    /// Computes homomorphically a bitor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_bitor(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 | msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitor(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<RadixCiphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_bitor(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let res = sks.checked_bitor_assign(&mut ct1, &ct2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 | msg2, clear);
    /// ```
    pub fn checked_bitor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitor_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitor between two ciphertexts encrypting integer values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 | msg2);
    /// ```
    pub fn smart_bitor(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitor(ct_left, ct_right)
    }

    pub fn smart_bitor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitor_assign(ct_left, ct_right);
    }

    /// Computes homomorphically bitxor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
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
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 49;
    /// let msg2 = 64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise xor:
    /// let ct_res = sks.unchecked_bitxor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 ^ msg2, dec);
    /// ```
    pub fn unchecked_bitxor(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitxor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter_mut().zip(ct_right.blocks.iter()) {
            self.key.unchecked_bitxor_assign(ct_left_i, ct_right_i);
        }
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_bitxor(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 ^ msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitxor(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<RadixCiphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_bitxor(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let res = sks.checked_bitxor_assign(&mut ct1, &ct2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 ^ msg2, clear);
    /// ```
    pub fn checked_bitxor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitxor_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitxor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 ^ msg2);
    /// ```
    pub fn smart_bitxor(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitxor(ct_left, ct_right)
    }

    pub fn smart_bitxor_assign(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.unchecked_bitxor_assign(ct_left, ct_right);
    }
}
