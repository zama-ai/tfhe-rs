use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::CheckError::CarryFull;
use crate::shortint::{CheckError, Ciphertext};

impl ServerKey {
    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 2;
    /// let clear_2 = 1;
    ///
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// let ct_res = sks.unchecked_bitand(&ct_1, &ct_2);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 & clear_2, res);
    /// ```
    pub fn unchecked_bitand(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_bitand(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt(clear_2);
    ///
    /// sks.unchecked_bitand_assign(&mut ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_1 & clear_2, res);
    /// ```
    pub fn unchecked_bitand_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_bitand_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute bitwise AND between two ciphertexts without checks.
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
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.checked_bitand(&ct1, &ct2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg & msg);
    /// ```
    pub fn checked_bitand(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_bitand(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute bitwise AND between two ciphertexts without checks.
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
    /// // Compute homomorphically an AND:
    /// let res = sks.checked_bitand_assign(&mut ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg & msg);
    /// ```
    pub fn checked_bitand_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitand_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically an AND between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.smart_bitand(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg & msg, res);
    /// ```
    pub fn smart_bitand(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitand(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically an AND between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// let modulus = 4;
    /// // Encrypt two messages:
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an AND:
    /// sks.smart_bitand_assign(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 & msg1) % modulus, res);
    /// ```
    pub fn smart_bitand_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitand_assign(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt(clear_2);
    ///
    /// let ct_res = sks.unchecked_bitxor(&ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 ^ clear_2, res);
    /// ```
    pub fn unchecked_bitxor(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_bitxor(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_1 = 2;
    /// let clear_2 = 0;
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let mut ct_right = cks.encrypt(clear_2);
    ///
    /// sks.smart_bitxor(&mut ct_left, &mut ct_right);
    ///
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_1 ^ clear_2, res);
    /// ```
    pub fn unchecked_bitxor_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_bitxor_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
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
    /// // Compute homomorphically a xor:
    /// let ct_res = sks.checked_bitxor(&ct1, &ct2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg ^ msg);
    /// ```
    pub fn checked_bitxor(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_bitxor(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
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
    /// // Compute homomorphically a xor:
    /// let res = sks.checked_bitxor_assign(&mut ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg ^ msg);
    /// ```
    pub fn checked_bitxor_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitxor_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically an XOR between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically a XOR:
    /// let ct_res = sks.smart_bitxor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg ^ msg, res);
    /// ```
    pub fn smart_bitxor(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitxor(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a XOR between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// let modulus = 4;
    /// // Encrypt two messages:
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a XOR:
    /// sks.smart_bitxor_assign(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 ^ msg1) % modulus, res);
    /// ```
    pub fn smart_bitxor_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitxor_assign(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute bitwise OR between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_left = 1;
    /// let clear_right = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(clear_left);
    /// let ct_right = cks.encrypt(clear_right);
    ///
    /// let ct_res = sks.unchecked_bitor(&ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_left | clear_right, res);
    /// ```
    pub fn unchecked_bitor(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_bitor(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute bitwise OR between two ciphertexts.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::DEFAULT_PARAMETERS;
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(DEFAULT_PARAMETERS);
    ///
    /// let clear_left = 2;
    /// let clear_right = 1;
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_left);
    /// let ct_right = cks.encrypt(clear_right);
    ///
    /// sks.unchecked_bitor_assign(&mut ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_left | clear_right, res);
    /// ```
    pub fn unchecked_bitor_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_bitor_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute bitwise OR between two ciphertexts without checks.
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
    /// // Compute homomorphically a or:
    /// let ct_res = sks.checked_bitor(&ct1, &ct2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg | msg);
    /// ```
    pub fn checked_bitor(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_bitor(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute bitwise OR between two ciphertexts without checks.
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
    /// // Compute homomorphically an or:
    /// let res = sks.checked_bitor_assign(&mut ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg | msg);
    /// ```
    pub fn checked_bitor_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.unchecked_bitor_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically an OR between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_bitor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg | msg, res);
    /// ```
    pub fn smart_bitor(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitor(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically an OR between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// let modulus = 4;
    /// // Encrypt two messages:
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an OR:
    /// sks.smart_bitor_assign(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 | msg1) % modulus, res);
    /// ```
    pub fn smart_bitor_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_bitor_assign(self, ct_left, ct_right).unwrap()
        })
    }
}
