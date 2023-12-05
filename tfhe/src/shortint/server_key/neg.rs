use super::CiphertextNoiseDegree;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::misc::divide_ceil;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the negation is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.neg(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.neg(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn neg(&self, ct: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct.clone();
        self.neg_assign(&mut ct_res);
        ct_res
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the negation is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn neg_assign(&self, ct: &mut Ciphertext) {
        if !ct.carry_is_empty() {
            self.message_extract_assign(ct);
        }
        self.unchecked_neg_assign(ct);
        self.message_extract_assign(ct);
    }

    /// Homomorphically negates a message without checks.
    ///
    /// Negation here means the opposite value in the modulo set.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
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
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let mut ct_res = sks.unchecked_neg(&ct);
    ///
    /// // Decrypt
    /// let three = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(modulus - msg, three);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let mut ct_res = sks.unchecked_neg(&ct);
    ///
    /// // Decrypt
    /// let three = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(modulus - msg, three);
    /// ```
    pub fn unchecked_neg(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_neg_assign(&mut result);
        result
    }

    pub fn unchecked_neg_with_correcting_term(&self, ct: &Ciphertext) -> (Ciphertext, u64) {
        let mut result = ct.clone();
        let z = self.unchecked_neg_assign_with_correcting_term(&mut result);
        (result, z)
    }

    /// Homomorphically negates a message inplace without checks.
    ///
    /// Negation here means the opposite value in the modulo set.
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
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.unchecked_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(modulus - msg, cks.decrypt(&ct));
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.unchecked_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(modulus - msg, cks.decrypt(&ct));
    /// ```
    pub fn unchecked_neg_assign(&self, ct: &mut Ciphertext) {
        let _z = self.unchecked_neg_assign_with_correcting_term(ct);
    }

    pub fn unchecked_neg_assign_with_correcting_term(&self, ct: &mut Ciphertext) -> u64 {
        // z = ceil( degree / 2^p ) * 2^p
        let msg_mod = ct.message_modulus.0;
        // Ensure z is always >= 1 (which would not be the case if degree == 0)
        // some algorithms (e.g. overflowing_sub) require this even for trivial zeros
        let mut z = divide_ceil(ct.degree.get(), msg_mod).max(1) as u64;
        z *= msg_mod as u64;

        // Value of the shift we multiply our messages by
        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        //Scaling + 1 on the padding bit
        let w = Plaintext(z * delta);

        // (0,Delta*z) - ct
        lwe_ciphertext_opposite_assign(&mut ct.ct);

        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, w);

        // Update the degree
        ct.degree = Degree::new(z as usize);

        z
    }

    /// Verify if a ciphertext can be negated.
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
    /// let msg = 2;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Check if we can perform a negation
    /// let can_be_negated = sks.is_neg_possible(ct.noise_degree()).unwrap();
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Check if we can perform a negation
    /// let can_be_negated = sks.is_neg_possible(ct.noise_degree()).unwrap();
    /// ```
    pub fn is_neg_possible(&self, ct: CiphertextNoiseDegree) -> Result<(), CheckError> {
        // z = ceil( degree / 2^p ) x 2^p
        let msg_mod = self.message_modulus.0;
        let mut z = (ct.degree.get() + msg_mod - 1) / msg_mod;
        z = z.wrapping_mul(msg_mod);

        self.max_degree.validate(Degree::new(z))
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise a [CheckError] is returned.
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
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// let ct_res = sks.checked_neg(&ct).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// let ct_res = sks.checked_neg(&ct).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn checked_neg(&self, ct: &Ciphertext) -> Result<Ciphertext, CheckError> {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        self.is_neg_possible(ct.noise_degree())?;
        let ct_result = self.unchecked_neg(ct);
        Ok(ct_result)
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise a [CheckError] is returned and the ciphertext is not .
    ///
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
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically the negation:
    /// sks.checked_neg_assign(&mut ct).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically the negation:
    /// sks.checked_neg_assign(&mut ct).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn checked_neg_assign(&self, ct: &mut Ciphertext) -> Result<(), CheckError> {
        self.is_neg_possible(ct.noise_degree())?;
        self.unchecked_neg_assign(ct);
        Ok(())
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the negation is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.smart_neg(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.smart_neg(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn smart_neg(&self, ct: &mut Ciphertext) -> Ciphertext {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ct.noise_degree()).is_err() {
            self.message_extract_assign(ct);
        }

        self.is_neg_possible(ct.noise_degree()).unwrap();

        self.unchecked_neg(ct)
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.smart_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.smart_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn smart_neg_assign(&self, ct: &mut Ciphertext) {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ct.noise_degree()).is_err() {
            self.message_extract_assign(ct);
        }
        self.is_neg_possible(ct.noise_degree()).unwrap();
        self.unchecked_neg_assign(ct);
    }
}
