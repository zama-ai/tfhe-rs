use super::CiphertextNoiseDegree;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, PaddingBit, ServerKey};

impl ServerKey {
    /// Compute homomorphically an addition between a ciphertext and a scalar.
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1_u64;
    /// let scalar = 9_u8;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_add(&ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((msg + scalar as u64) % modulus, clear);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.scalar_add(&ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!((msg + scalar as u64) % modulus, clear);
    /// ```
    pub fn scalar_add(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.scalar_add_assign(&mut ct_res, scalar);
        ct_res
    }

    /// Compute homomorphically an addition of a ciphertext by a scalar.
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1_u64;
    /// let scalar = 5_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_add_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(
    ///     (msg + scalar as u64) % cks.parameters.message_modulus().0,
    ///     clear
    /// );
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.scalar_add_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(
    ///     (msg + scalar as u64) % cks.parameters.message_modulus().0,
    ///     clear
    /// );
    /// ```
    pub fn scalar_add_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        let modulus = self.message_modulus.0;
        let acc = self.generate_lookup_table(|x| (scalar as u64 + x) % modulus);
        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Compute homomorphically an addition between a ciphertext and a scalar.
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// let ct_res = sks.unchecked_scalar_add(&ct, 2);
    ///
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// let ct_res = sks.unchecked_scalar_add(&ct, 2);
    ///
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_add(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.unchecked_scalar_add_assign(&mut ct_result, scalar);
        ct_result
    }

    /// Compute homomorphically an addition between a ciphertext and a scalar.
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// sks.unchecked_scalar_add_assign(&mut ct, 2);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// sks.unchecked_scalar_add_assign(&mut ct, 2);
    ///
    /// let clear = cks.decrypt(&ct);
    /// assert_eq!(3, clear);
    /// ```
    pub fn unchecked_scalar_add_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        let encoded_scalar = self
            .encoding(PaddingBit::Yes)
            .encode(Cleartext(u64::from(scalar)));
        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, encoded_scalar);

        ct.degree = Degree::new(ct.degree.get() + u64::from(scalar));
    }

    /// Verify if a scalar can be added to the ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(2);
    ///
    /// // Verification if the scalar addition can be computed:
    /// sks.is_scalar_add_possible(ct.noise_degree(), 3).unwrap();
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(2);
    ///
    /// // Verification if the scalar addition can be computed:
    /// sks.is_scalar_add_possible(ct.noise_degree(), 3).unwrap();
    /// ```
    pub fn is_scalar_add_possible(
        &self,
        ct: CiphertextNoiseDegree,
        scalar: u8,
    ) -> Result<(), CheckError> {
        let final_degree = u64::from(scalar) + ct.degree.get();

        self.max_degree.validate(Degree::new(final_degree))
    }

    /// Compute homomorphically an addition between a ciphertext and a scalar.
    ///
    /// If the operation is possible, the result is returned in a _new_ ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a addition multiplication:
    /// let ct_res = sks.checked_scalar_add(&ct, 2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a addition multiplication:
    /// let ct_res = sks.checked_scalar_add(&ct, 2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_add(
        &self,
        ct: &Ciphertext,
        scalar: u8,
    ) -> Result<Ciphertext, CheckError> {
        //If the ciphertext cannot be multiplied without exceeding the max degree
        self.is_scalar_add_possible(ct.noise_degree(), scalar)?;
        let ct_result = self.unchecked_scalar_add(ct, scalar);
        Ok(ct_result)
    }

    /// Compute homomorphically an addition between a ciphertext and a scalar.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise a [CheckError] is returned and the ciphertext is not
    /// modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// sks.checked_scalar_add_assign(&mut ct, 2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(1);
    ///
    /// // Compute homomorphically a scalar addition:
    /// sks.checked_scalar_add_assign(&mut ct, 2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// assert_eq!(clear_res, 3);
    /// ```
    pub fn checked_scalar_add_assign(
        &self,
        ct: &mut Ciphertext,
        scalar: u8,
    ) -> Result<(), CheckError> {
        self.is_scalar_add_possible(ct.noise_degree(), scalar)?;
        self.unchecked_scalar_add_assign(ct, scalar);
        Ok(())
    }

    /// Compute homomorphically an addition between a ciphertext and a scalar.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This checks that the scalar addition is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1_u64;
    /// let scalar = 9_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_add(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(2, clear % modulus);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// let ct_res = sks.smart_scalar_add(&mut ct, scalar);
    ///
    /// // The input ciphertext content is not changed
    /// assert_eq!(cks.decrypt(&ct), msg);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(2, clear % modulus);
    /// ```
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_add(&self, ct: &mut Ciphertext, scalar: u8) -> Ciphertext {
        let mut ct_result = ct.clone();
        self.smart_scalar_add_assign(&mut ct_result, scalar);

        ct_result
    }

    /// Compute homomorphically an addition of a ciphertext by a scalar.
    ///
    /// The result is _stored_ in the `ct` ciphertext.
    ///
    /// This checks that the scalar addition is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1_u64;
    /// let scalar = 5_u8;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_add_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(6, clear);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a scalar multiplication:
    /// sks.smart_scalar_add_assign(&mut ct, scalar);
    ///
    /// // Our result is what we expect
    /// let clear = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(6, clear);
    /// ```
    pub fn smart_scalar_add_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        // Direct scalar computation is possible
        if self
            .is_scalar_add_possible(ct.noise_degree(), scalar)
            .is_ok()
        {
            self.unchecked_scalar_add_assign(ct, scalar);
        } else {
            // If the scalar is too large, PBS is used to compute the scalar mul
            let acc = self.generate_msg_lookup_table(|x| scalar as u64 + x, self.message_modulus);
            self.apply_lookup_table_assign(ct, &acc);
            ct.degree = Degree::new(self.message_modulus.0 - 1);
        }
    }
}
