use crate::integer::{CrtCiphertext, ServerKey};
use crate::shortint::CheckError;

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
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// let ctxt = sks.unchecked_crt_sub(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_sub(
        &self,
        ctxt_left: &CrtCiphertext,
        ctxt_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut result = ctxt_left.clone();
        self.unchecked_crt_sub_assign(&mut result, ctxt_right);
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
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// let ctxt = sks.unchecked_crt_sub(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_sub_assign(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &CrtCiphertext,
    ) {
        let neg = self.unchecked_crt_neg(ctxt_right);
        self.unchecked_crt_add_assign(ctxt_left, &neg);
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// let ctxt = sks.smart_crt_sub(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_sub(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_crt_sub_possible(ctxt_left, ctxt_right).is_err() {
            self.full_extract_message_assign(ctxt_left);
            self.full_extract_message_assign(ctxt_right);
        }

        self.is_crt_sub_possible(ctxt_left, ctxt_right).unwrap();

        let mut result = ctxt_left.clone();
        self.unchecked_crt_sub_assign(&mut result, ctxt_right);

        result
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 5;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// sks.smart_crt_sub_assign(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_sub_assign(
        &self,
        ctxt_left: &mut CrtCiphertext,
        ctxt_right: &mut CrtCiphertext,
    ) {
        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_crt_sub_possible(ctxt_left, ctxt_right).is_err() {
            self.full_extract_message_assign(ctxt_left);
            self.full_extract_message_assign(ctxt_right);
        }

        self.is_crt_sub_possible(ctxt_left, ctxt_right).unwrap();

        self.unchecked_crt_sub_assign(ctxt_left, ctxt_right);
    }

    pub fn is_crt_sub_possible(
        &self,
        ctxt_left: &CrtCiphertext,
        ctxt_right: &CrtCiphertext,
    ) -> Result<(), CheckError> {
        for (ct_left_i, ct_right_i) in ctxt_left.blocks.iter().zip(ctxt_right.blocks.iter()) {
            self.key
                .is_sub_possible(ct_left_i.noise_degree(), ct_right_i.noise_degree())?;
        }
        Ok(())
    }
}
