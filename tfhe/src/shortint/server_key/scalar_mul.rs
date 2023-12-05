use super::CiphertextNoiseDegree;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::lwe_encryption::trivially_encrypt_lwe_ciphertext;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_mul(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(msg * scalar as u64 % modulus, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_mul(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(msg * scalar as u64 % modulus, clear);
    /// ```
    pub fn scalar_mul(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.scalar_mul_assign(&mut ct_res, scalar);
        ct_res
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_mul_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(
    ///     msg * scalar as u64 % cks.parameters.message_modulus().0 as u64,
    ///     clear
    /// );
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_mul_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(
    ///     msg * scalar as u64 % cks.parameters.message_modulus().0 as u64,
    ///     clear
    /// );
    /// ```
    pub fn scalar_mul_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        let acc = self.generate_msg_lookup_table(|x| scalar as u64 * x, self.message_modulus);
        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.unchecked_scalar_mul(&ct, 3);
    ///
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.unchecked_scalar_mul(&ct, 3);
    ///
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_mul(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.unchecked_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.unchecked_scalar_mul_assign(&mut ct, 3);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.unchecked_scalar_mul_assign(&mut ct, 3);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_mul_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        unchecked_scalar_mul_assign(ct, scalar);
    }

    /// Multiply one ciphertext with a scalar in the case the carry space cannot fit the product
    /// applying the message space modulus in the process.
    ///
    /// This is a bootstrapped operation.
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
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_scalar_mul_lsb_small_carry_modulus_assign(&mut ct_1, clear_2 as u8);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_2 * clear_1, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_scalar_mul_lsb_small_carry_modulus_assign(&mut ct_1, clear_2 as u8);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_2 * clear_1, res);
    /// ```
    pub fn unchecked_scalar_mul_lsb_small_carry_modulus_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) {
        // Modulus of the msg in the msg bits
        let modulus = ct.message_modulus.0 as u64;

        let acc_mul = self.generate_lookup_table(|x| (x.wrapping_mul(scalar as u64)) % modulus);

        self.apply_lookup_table_assign(ct, &acc_mul);
    }

    /// Verify if the ciphertext can be multiplied by a scalar.
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
    /// let ct = cks.encrypt(2);
    ///
    /// // Verification if the scalar multiplication can be computed:
    /// sks.is_scalar_mul_possible(ct.noise_degree(), 3).unwrap();
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(2);
    ///
    /// // Verification if the scalar multiplication can be computed:
    /// sks.is_scalar_mul_possible(ct.noise_degree(), 3).unwrap();
    /// ```
    pub fn is_scalar_mul_possible(
        &self,
        ct: CiphertextNoiseDegree,
        scalar: u8,
    ) -> Result<(), CheckError> {
        //scalar * ct.counter
        let final_degree = scalar as usize * ct.degree.get();

        self.max_degree.validate(Degree::new(final_degree))?;

        self.max_noise_level
            .validate(ct.noise_level * scalar as usize)?;

        Ok(())
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is returned in a _new_ ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// The operation is modulo the precision bits to the power of two.
    ///
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
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.checked_scalar_mul(&ct, 3).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.checked_scalar_mul(&ct, 3).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_mul(
        &self,
        ct: &Ciphertext,
        scalar: u8,
    ) -> Result<Ciphertext, CheckError> {
        //If the ciphertext cannot be multiplied without exceeding the degree max
        self.is_scalar_mul_possible(ct.noise_degree(), scalar)?;
        let ct_result = self.unchecked_scalar_mul(ct, scalar);
        Ok(ct_result)
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise a [CheckError] is returned and the ciphertext is not .
    ///
    /// The operation is modulo the precision bits to the power of two.
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
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.checked_scalar_mul_assign(&mut ct, 3).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.checked_scalar_mul_assign(&mut ct, 3).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_mul_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> Result<(), CheckError> {
        self.is_scalar_mul_possible(ct.noise_degree(), scalar)?;
        self.unchecked_scalar_mul_assign(ct, scalar);
        Ok(())
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// This checks that the multiplication is possible. In the case where the carry buffers are
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// // Encrypt a message
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
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(3, clear % modulus);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
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
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(3, clear % modulus);
    /// ```
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_mul(&self, ct: &mut Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.smart_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    /// Compute homomorphically a multiplication of a ciphertext by a scalar.
    ///
    /// This checks that the multiplication is possible. In the case where the carry buffers are
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
    /// let msg = 1_u64;
    /// let scalar = 3_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_mul_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
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
        // Direct scalar computation is possible
        if self
            .is_scalar_mul_possible(ct.noise_degree(), scalar)
            .is_ok()
        {
            self.unchecked_scalar_mul_assign(ct, scalar);
            ct.degree = Degree::new(ct.degree.get() * scalar as usize);
        }
        // If the ciphertext cannot be multiplied without exceeding the degree max
        else {
            self.evaluate_msg_univariate_function_assign(ct, |x| scalar as u64 * x);
            ct.degree = Degree::new(self.message_modulus.0 - 1);
        }
    }
}

pub(crate) fn unchecked_scalar_mul_assign(ct: &mut Ciphertext, scalar: u8) {
    ct.set_noise_level(ct.noise_level() * scalar as usize);
    ct.degree = Degree::new(ct.degree.get() * scalar as usize);

    match scalar {
        0 => {
            trivially_encrypt_lwe_ciphertext(&mut ct.ct, Plaintext(0));
        }
        1 => {
            // Multiplication by one is the identidy
        }
        scalar => {
            let scalar = u64::from(scalar);
            let cleartext_scalar = Cleartext(scalar);
            lwe_ciphertext_cleartext_mul_assign(&mut ct.ct, cleartext_scalar);
        }
    }
}
