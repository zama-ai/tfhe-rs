use crate::integer::{CrtCiphertext, ServerKey};

impl ServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    /// let mut ctxt_2 = cks.encrypt_crt(clear_2, basis.clone());
    ///
    /// let ctxt = sks.unchecked_crt_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_sub_parallelized(
        &self,
        ctxt_left: &CrtCiphertext,
        ctxt_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut result = ctxt_left.clone();
        self.unchecked_crt_sub_assign_parallelized(&mut result, ctxt_right);
        result
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    /// let mut ctxt_2 = cks.encrypt_crt(clear_2, basis.clone());
    ///
    /// let ctxt = sks.unchecked_crt_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_sub_assign_parallelized(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &CrtCiphertext,
    ) {
        let neg = self.unchecked_crt_neg_parallelized(ctxt_right);
        self.unchecked_crt_add_assign_parallelized(ctxt_left, &neg);
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    /// let mut ctxt_2 = cks.encrypt_crt(clear_2, basis.clone());
    ///
    /// let ctxt = sks.smart_crt_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn smart_crt_sub_parallelized(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_crt_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_extract_message_assign_parallelized(ctxt_left),
                || self.full_extract_message_assign_parallelized(ctxt_right),
            );
        }

        self.unchecked_crt_sub_parallelized(ctxt_left, ctxt_right)
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    /// let mut ctxt_2 = cks.encrypt_crt(clear_2, basis.clone());
    ///
    /// sks.smart_crt_sub_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn smart_crt_sub_assign_parallelized(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &mut CrtCiphertext,
    ) {
        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_crt_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_extract_message_assign_parallelized(ctxt_left),
                || self.full_extract_message_assign_parallelized(ctxt_right),
            );
        }

        self.unchecked_crt_sub_assign_parallelized(ctxt_left, ctxt_right);
    }
}
