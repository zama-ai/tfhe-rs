use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::{CiphertextBase, PBSOrderMarker};

impl ServerKey {
    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Same thing using the small key for encryption
    /// let msg1 = 1;
    /// let msg2 = 2;
    /// let ct1 = cks.encrypt_small(msg1);
    /// let ct2 = cks.encrypt_small(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 + msg2, res);
    /// ```
    pub fn unchecked_add<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_add(ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// let mut ct_left = cks.encrypt_small(msg);
    /// let ct_right = cks.encrypt_small(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.unchecked_add_assign(&mut ct_left, &ct_right);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_left);
    /// assert_eq!(msg + msg, two);
    /// ```
    pub fn unchecked_add_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_add_assign(ct_left, ct_right).unwrap()
        })
    }

    /// Verify if ct_left and ct_right can be added together.
    ///
    /// This checks that the sum of their degree is
    /// smaller than the maximum degree.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 2u64;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let can_be_added = sks.is_add_possible(&ct_left, &ct_right);
    ///
    /// assert_eq!(can_be_added, true);
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt_small(msg);
    /// let ct_right = cks.encrypt_small(msg);
    ///
    /// // Check if we can perform an addition
    /// let can_be_added = sks.is_add_possible(&ct_left, &ct_right);
    ///
    /// assert_eq!(can_be_added, true);
    /// ```
    pub fn is_add_possible<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> bool {
        let final_operation_count = ct_left.degree.0 + ct_right.degree.0;
        final_operation_count <= self.max_degree.0
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt_small(msg);
    /// let ct2 = cks.encrypt_small(msg);
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
    pub fn checked_add<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> Result<CiphertextBase<OpOrder>, CheckError> {
        if self.is_add_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_add(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt_small(msg);
    /// let ct_right = cks.encrypt_small(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let res = sks.checked_add_assign(&mut ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg + msg);
    /// ```
    pub fn checked_add_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> Result<(), CheckError> {
        if self.is_add_possible(ct_left, ct_right) {
            self.unchecked_add_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt_small(msg);
    /// let mut ct2 = cks.encrypt_small(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, two);
    /// ```
    pub fn smart_add<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_add(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically an addition between two ciphertexts
    ///
    /// The result is stored in the `ct_left` cipher text.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
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
    ///
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt_small(msg1);
    /// let mut ct2 = cks.encrypt_small(msg2);
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
    pub fn smart_add_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_add_assign(self, ct_left, ct_right).unwrap()
        })
    }
}
