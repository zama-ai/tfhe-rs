use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// The operation is modulo the the precision bits to the power of two.
    ///
    /// This function does _not_ check whether the capacity of the ciphertext is exceeded.
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
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.unchecked_scalar_mul(&ct, 3);
    ///
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_mul(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_mul(ct, scalar).unwrap()
        })
    }

    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// The result it stored in the given ciphertext.
    ///
    /// The operation is modulo the the precision bits to the power of two.
    ///
    /// This function does not check whether the capacity of the ciphertext is exceeded.
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
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.unchecked_scalar_mul_assign(&mut ct, 3);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_mul_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_mul_assign(ct, scalar).unwrap()
        })
    }

    /// Verifies if the ciphertext can be multiplied by a scalar.
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
    /// let ct = cks.encrypt(2);
    ///
    /// // Verification if the scalar multiplication can be computed:
    /// let can_be_computed = sks.is_scalar_mul_possible(&ct, 3);
    ///
    /// assert_eq!(can_be_computed, true);
    /// ```
    pub fn is_scalar_mul_possible(&self, ct: &Ciphertext, scalar: u8) -> bool {
        //scalar * ct.counter
        let final_degree = scalar as usize * ct.degree.0;

        final_degree <= self.max_degree.0
    }

    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is returned in a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// The operation is modulo the precision bits to the power of two.
    ///
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
    /// // Encrypt a message:
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.checked_scalar_mul(&ct, 3);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_mul(
        &self,
        ct: &Ciphertext,
        scalar: u8,
    ) -> Result<Ciphertext, CheckError> {
        //If the ciphertext cannot be multiplied without exceeding the degree max
        if self.is_scalar_mul_possible(ct, scalar) {
            let ct_result = self.unchecked_scalar_mul(ct, scalar);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned and the ciphertext is not .
    ///
    /// The operation is modulo the precision bits to the power of two.
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
    /// // Encrypt a message:
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let res = sks.checked_scalar_mul_assign(&mut ct, 3);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_mul_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> Result<(), CheckError> {
        if self.is_scalar_mul_possible(ct, scalar) {
            self.unchecked_scalar_mul_assign(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// This checks that the multiplication is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_mul(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(3, clear % modulus);
    /// ```
    pub fn smart_scalar_mul(&self, ct: &mut Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_mul(self, ct, scalar).unwrap()
        })
    }

    /// Computes homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// This checks that the multiplication is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_mul_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    /// ```
    pub fn smart_scalar_mul_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_mul_assign(self, ct, scalar).unwrap()
        })
    }
}
