use super::{CiphertextNoiseDegree, SmartCleaningOperation};
use crate::core_crypto::algorithms::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, two);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct_res);
    /// assert_eq!(msg + msg, two);
    /// ```
    pub fn add(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.add_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute homomorphically an addition between two ciphertexts
    ///
    /// The result is stored in the `ct_left` ciphertext.
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
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.add_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct1);
    ///
    /// // 15 + 3 mod 4 -> 3 + 3 mod 4 -> 2 mod 4
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!((msg2 + msg1) % modulus, two);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.add_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let two = cks.decrypt(&ct1);
    ///
    /// // 15 + 3 mod 4 -> 3 + 3 mod 4 -> 2 mod 4
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!((msg2 + msg1) % modulus, two);
    /// ```
    pub fn add_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        let tmp_rhs: Ciphertext;

        if !ct_left.carry_is_empty() {
            self.message_extract_assign(ct_left);
        }

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
            &tmp_rhs
        };

        self.unchecked_add_assign(ct_left, rhs);
        self.message_extract_assign(ct_left);
    }

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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Same thing using the small key for encryption
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
        let mut result = ct_left.clone();
        self.unchecked_add_assign(&mut result, ct_right);
        result
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
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
        unchecked_add_assign(ct_left, ct_right);
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2u64;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let can_be_added = sks
    ///     .is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())
    ///     .unwrap();
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// let can_be_added = sks
    ///     .is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())
    ///     .unwrap();
    /// ```
    pub fn is_add_possible(
        &self,
        ct_left: CiphertextNoiseDegree,
        ct_right: CiphertextNoiseDegree,
    ) -> Result<(), CheckError> {
        self.max_degree.validate(ct_left.degree + ct_right.degree)?;

        self.max_noise_level
            .validate(ct_left.noise_level + ct_right.noise_level)?;
        Ok(())
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_add(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg + msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_add(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg + msg);
    /// ```
    pub fn checked_add(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        let ct_result = self.unchecked_add(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.checked_add_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg + msg);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.checked_add_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg + msg);
    /// ```
    pub fn checked_add_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        self.unchecked_add_assign(ct_left, ct_right);
        Ok(())
    }

    /// Compute homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
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
        let SmartCleaningOperation {
            bootstrap_left,
            bootstrap_right,
        } = self
            .binary_smart_op_optimal_cleaning_strategy(ct_left, ct_right, |sk, a, b| {
                sk.is_add_possible(a, b).is_ok()
            })
            .unwrap();

        if bootstrap_left {
            self.message_extract_assign(ct_left)
        }

        if bootstrap_right {
            self.message_extract_assign(ct_right)
        }

        self.is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())
            .unwrap();

        self.unchecked_add(ct_left, ct_right)
    }

    /// Compute homomorphically an addition between two ciphertexts
    ///
    /// The result is stored in the `ct_left` cipher text.
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
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!((msg2 + msg1) % modulus, two);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
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
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    /// assert_eq!((msg2 + msg1) % modulus, two);
    /// ```
    pub fn smart_add_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        let SmartCleaningOperation {
            bootstrap_left,
            bootstrap_right,
        } = self
            .binary_smart_op_optimal_cleaning_strategy(ct_left, ct_right, |sk, a, b| {
                sk.is_add_possible(a, b).is_ok()
            })
            .unwrap();

        if bootstrap_left {
            self.message_extract_assign(ct_left)
        }

        if bootstrap_right {
            self.message_extract_assign(ct_right)
        }

        self.is_add_possible(ct_left.noise_degree(), ct_right.noise_degree())
            .unwrap();

        self.unchecked_add_assign(ct_left, ct_right);
    }
}

pub(crate) fn unchecked_add_assign(ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
    lwe_ciphertext_add_assign(&mut ct_left.ct, &ct_right.ct);
    ct_left.degree = Degree::new(ct_left.degree.get() + ct_right.degree.get());
    ct_left.set_noise_level(ct_left.noise_level() + ct_right.noise_level());
}
