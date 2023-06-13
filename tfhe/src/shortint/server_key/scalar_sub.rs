use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    /// let scalar = 3;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_sub(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(msg - scalar as u64, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_sub(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(msg - scalar as u64, clear);
    /// ```
    pub fn scalar_sub(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.scalar_sub_assign(&mut ct_res, scalar);
        ct_res
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result is _stored_ in the `ct` ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 5;
    /// let scalar = 3;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_sub_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(msg - scalar as u64, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_sub_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(msg - scalar as u64, clear);
    /// ```
    pub fn scalar_sub_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        let modulus = self.message_modulus.0 as u64;
        let acc = self.generate_lookup_table(|x| (x.wrapping_sub(scalar as u64)) % modulus);
        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This function does _not_ check whether the capacity of the ciphertext is exceeded.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// let ct_res = sks.unchecked_scalar_sub(&ct, 6);
    ///
    /// // 5 - 6 mod 4 = 3 mod 4
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// let ct_res = sks.unchecked_scalar_sub(&ct, 6);
    ///
    /// // 5 - 6 mod 4 = 3 mod 4
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_sub(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_sub(ct, scalar).unwrap()
        })
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result it stored in the given ciphertext.
    ///
    /// This function does not check whether the capacity of the ciphertext is exceeded.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// sks.unchecked_scalar_sub_assign(&mut ct, 2);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// sks.unchecked_scalar_sub_assign(&mut ct, 2);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_sub_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_sub_assign(ct, scalar).unwrap()
        })
    }

    /// Verify if a scalar can be subtracted to the ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Verification if the scalar subtraction can be computed:
    /// let can_be_computed = sks.is_scalar_sub_possible(&ct, 3);
    ///
    /// assert_eq!(can_be_computed, true);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Verification if the scalar subtraction can be computed:
    /// let can_be_computed = sks.is_scalar_sub_possible(&ct, 3);
    ///
    /// assert_eq!(can_be_computed, true);
    /// ```
    pub fn is_scalar_sub_possible(&self, ct: &Ciphertext, scalar: u8) -> bool {
        let neg_scalar = u64::from(scalar.wrapping_neg()) % self.message_modulus.0 as u64;
        let final_degree = neg_scalar as usize + ct.degree.0;
        final_degree <= self.max_degree.0
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is returned in a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a subtraction multiplication:
    /// let ct_res = sks.checked_scalar_sub(&ct, 2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a subtraction multiplication:
    /// let ct_res = sks.checked_scalar_sub(&ct, 2);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let ct_res = ct_res.unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_sub(
        &self,
        ct: &Ciphertext,
        scalar: u8,
    ) -> Result<Ciphertext, CheckError> {
        //If the scalar subtraction cannot be done without exceeding the max degree
        if self.is_scalar_sub_possible(ct, scalar) {
            let ct_result = self.unchecked_scalar_sub(ct, scalar);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned and the ciphertext is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// let res = sks.checked_scalar_sub_assign(&mut ct, 2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(5);
    ///
    /// // Compute homomorphically a scalar subtraction:
    /// let res = sks.checked_scalar_sub_assign(&mut ct, 2);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_sub_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> Result<(), CheckError> {
        if self.is_scalar_sub_possible(ct, scalar) {
            self.unchecked_scalar_sub_assign(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This checks that the scalar subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    /// let scalar = 3;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_sub(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(msg - scalar as u64, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_sub(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    ///
    /// assert_eq!(msg - scalar as u64, clear);
    /// ```
    pub fn smart_scalar_sub(&self, ct: &mut Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_sub(self, ct, scalar).unwrap()
        })
    }

    /// Compute homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// The result is _stored_ in the `ct` ciphertext.
    ///
    /// This checks that the scalar subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 5;
    /// let scalar = 3;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_sub_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(msg - scalar as u64, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_sub_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(msg - scalar as u64, clear);
    /// ```
    pub fn smart_scalar_sub_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_sub_assign(self, ct, scalar).unwrap()
        })
    }
}
