use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This function computes the addition without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg1 = 1;
    /// let msg2 = 2;
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 + msg2, res);
    /// ```
    pub fn unchecked_add(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_add(ct_left, ct_right).unwrap()
        })
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// The result is _stored_ in the `ct_left` ciphertext.
    ///
    /// This function computes the addition without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    ///
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.unchecked_add_assign(&mut ct_left, &ct_right);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_left);
    /// assert_eq!(msg + msg, two);
    /// ```
    pub fn unchecked_add_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_add_assign(ct_left, ct_right).unwrap()
        })
    }

    /// Verifies if ct_left and ct_right can be added together.
    ///
    /// This checks that the sum of their degree is
    /// smaller than the maximum degree.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let can_be_added = sks.is_add_possible(&ct_left, &ct_right);
    ///
    /// assert_eq!(can_be_added, true);
    /// ```
    pub fn is_add_possible(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> bool {
        let final_operation_count = ct_left.degree.0 + ct_right.degree.0;
        final_operation_count <= self.max_degree.0
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_add(&ct1, &ct2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg + msg);
    /// ```
    pub fn checked_add(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_add_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_add(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let res = sks.checked_add_assign(&mut ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg + msg);
    /// ```
    pub fn checked_add_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        if self.is_add_possible(ct_left, ct_right) {
            self.unchecked_add_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, two);
    /// ```
    pub fn smart_add(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_add(self, ct_left, ct_right).unwrap()
        })
    }

    /// Computes homomorphically an addition between two ciphertexts
    ///
    /// The result is stored in the `ct_left` cipher text.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.smart_add_assign(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct1);
    ///
    /// // 15 + 3 mod 4 -> 3 + 3 mod 4 -> 2 mod 4
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!((msg2 + msg1) % modulus, two);
    /// ```
    pub fn smart_add_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_add_assign(self, ct_left, ct_right).unwrap()
        })
    }
}
