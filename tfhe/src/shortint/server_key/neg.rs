use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

impl ServerKey {
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
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (mut cks, mut sks) = gen_keys(Parameters::default());
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
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(modulus - msg, three);
    /// ```
    pub fn unchecked_neg(&self, ct: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.unchecked_neg(self, ct).unwrap())
    }

    pub fn unchecked_neg_with_correcting_term(&self, ct: &Ciphertext) -> (Ciphertext, u64) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_neg_with_correcting_term(self, ct).unwrap()
        })
    }

    /// Homomorphically negates a message inplace without checks.
    ///
    /// Negation here means the opposite value in the modulo set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt a message
    /// let msg = 3;
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.unchecked_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(modulus - msg, cks.decrypt(&ct));
    /// ```
    pub fn unchecked_neg_assign(&self, ct: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_neg_assign(self, ct).unwrap()
        })
    }

    pub fn unchecked_neg_assign_with_correcting_term(&self, ct: &mut Ciphertext) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_neg_assign_with_correcting_term(self, ct)
                .unwrap()
        })
    }

    /// Verify if a ciphertext can be negated.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt a message
    /// let msg = 2;
    /// let ct = cks.encrypt(msg);
    ///
    /// // Check if we can perform a negation
    /// let can_be_negated = sks.is_neg_possible(&ct);
    ///
    /// assert_eq!(can_be_negated, true);
    /// ```
    pub fn is_neg_possible(&self, ct: &Ciphertext) -> bool {
        // z = ceil( degree / 2^p ) x 2^p
        let msg_mod = self.message_modulus.0;
        let mut z = (ct.degree.0 + msg_mod - 1) / msg_mod;
        z = z.wrapping_mul(msg_mod);

        // counter = z / (2^p-1)
        let counter = z / (self.message_modulus.0 - 1);

        counter <= self.max_degree.0
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt a message
    /// let msg = 1;
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// let ct_res = sks.checked_neg(&ct);
    ///
    /// assert!(ct_res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct_res.unwrap());
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn checked_neg(&self, ct: &Ciphertext) -> Result<Ciphertext, CheckError> {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ct) {
            let ct_result = self.unchecked_neg(ct);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// If the operation is possible, the result is stored _in_ the input ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned and the ciphertext is not .
    ///
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt a message:
    /// let msg = 1;
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically the negation:
    /// let res = sks.checked_neg_assign(&mut ct);
    ///
    /// assert!(res.is_ok());
    ///
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn checked_neg_assign(&self, ct: &mut Ciphertext) -> Result<(), CheckError> {
        if self.is_neg_possible(ct) {
            self.unchecked_neg_assign(ct);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the negation is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let msg = 3;
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.smart_neg(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn smart_neg(&self, ct: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| engine.smart_neg(self, ct).unwrap())
    }

    /// Compute homomorphically a negation of a ciphertext.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::{gen_keys, Parameters};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(Parameters::default());
    ///
    /// // Encrypt two messages:
    /// let msg = 3;
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.smart_neg_assign(&mut ct);
    ///
    /// // Decrypt
    /// let clear_res = cks.decrypt(&ct);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res, modulus - msg);
    /// ```
    pub fn smart_neg_assign(&self, ct: &mut Ciphertext) {
        ShortintEngine::with_thread_local_mut(|engine| engine.smart_neg_assign(self, ct).unwrap())
    }
}
