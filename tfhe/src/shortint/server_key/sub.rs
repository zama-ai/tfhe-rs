use super::{CiphertextNoiseDegree, SmartCleaningOperation};
use crate::core_crypto::algorithms::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::CheckError;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This returns a new ciphertext.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.sub(&ct_1, &ct_2);
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn sub(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.sub_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This stores the result in `ct_left`
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.sub_assign(&mut ct_1, &ct_2);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(cks.decrypt(&ct_1) % modulus, 2);
    /// ```
    pub fn sub_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
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

        self.unchecked_sub_assign(ct_left, rhs);
        self.message_extract_assign(ct_left);
    }

    /// Homomorphically subtracts ct_right to ct_left.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This function computes the subtraction without checking
    /// if it exceeds the capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.unchecked_sub(&ct_1, &ct_2);
    ///
    /// // Decrypt:
    /// assert_eq!(cks.decrypt(&ct_res), 2 - 1);
    /// ```
    pub fn unchecked_sub(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_sub_assign(&mut result, ct_right);

        result
    }

    /// Homomorphically subtracts ct_right to ct_left.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// This function computes the subtraction without checking
    /// if it exceeds the capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.unchecked_sub_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt:
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(cks.decrypt(&ct_1) % modulus, 1);
    /// ```
    pub fn unchecked_sub_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_sub_assign_with_correcting_term(ct_left, ct_right);
    }

    /// Verify if ct_right can be subtracted to ct_left.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an subtraction
    /// sks.is_sub_possible(ct_1.noise_degree(), ct_2.noise_degree())
    ///     .unwrap();
    /// ```
    pub fn is_sub_possible(
        &self,
        ct_left: CiphertextNoiseDegree,
        ct_right: CiphertextNoiseDegree,
    ) -> Result<(), CheckError> {
        // z = ceil( degree / 2^p ) x 2^p
        let msg_mod = self.message_modulus.0;
        let mut z = ct_right.degree.get().div_ceil(msg_mod);
        z = z.wrapping_mul(msg_mod);

        let final_operation_count = ct_left.degree.get() + z;

        self.max_degree
            .validate(Degree::new(final_operation_count))?;

        self.max_noise_level
            .validate(ct_left.noise_level + ct_right.noise_level)?;
        Ok(())
    }

    /// Compute homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.checked_sub(&ct_1, &ct_2).unwrap();
    ///
    /// let modulus = cks.parameters.message_modulus().0;
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_sub(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        // If the ciphertexts cannot be subtracted without exceeding the degree max
        self.is_sub_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        let ct_result = self.unchecked_sub(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.checked_sub_assign(&mut ct_1, &ct_2).unwrap();
    /// let modulus = cks.parameters.message_modulus().0;
    /// let clear_res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_sub_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_sub_possible(ct_left.noise_degree(), ct_right.noise_degree())?;
        self.unchecked_sub_assign(ct_left, ct_right);
        Ok(())
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let mut ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.smart_sub(&mut ct_1, &mut ct_2);
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn smart_sub(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        let SmartCleaningOperation {
            bootstrap_left,
            bootstrap_right,
        } = self
            .binary_smart_op_optimal_cleaning_strategy(
                ct_left,
                ct_right,
                |sk, ct_left, ct_right| sk.is_sub_possible(ct_left, ct_right).is_ok(),
            )
            .unwrap();

        if bootstrap_left {
            self.message_extract_assign(ct_left)
        }

        if bootstrap_right {
            self.message_extract_assign(ct_right)
        }

        self.is_sub_possible(ct_left.noise_degree(), ct_right.noise_degree())
            .unwrap();

        self.unchecked_sub(ct_left, ct_right)
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let mut ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.smart_sub_assign(&mut ct_1, &mut ct_2);
    /// let modulus = cks.parameters.message_modulus().0;
    /// assert_eq!(cks.decrypt(&ct_1) % modulus, 2);
    /// ```
    pub fn smart_sub_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        let SmartCleaningOperation {
            bootstrap_left,
            bootstrap_right,
        } = self
            .binary_smart_op_optimal_cleaning_strategy(
                ct_left,
                ct_right,
                |sk, ct_left, ct_right| sk.is_sub_possible(ct_left, ct_right).is_ok(),
            )
            .unwrap();

        if bootstrap_left {
            self.message_extract_assign(ct_left)
        }

        if bootstrap_right {
            self.message_extract_assign(ct_right)
        }

        self.is_sub_possible(ct_left.noise_degree(), ct_right.noise_degree())
            .unwrap();

        self.unchecked_sub_assign(ct_left, ct_right);
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn unchecked_sub_with_correcting_term(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> (Ciphertext, u64) {
        let mut result = ct_left.clone();
        let z = self.unchecked_sub_assign_with_correcting_term(&mut result, ct_right);

        (result, z)
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn unchecked_sub_assign_with_correcting_term(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> u64 {
        let (neg_right, z) = self.unchecked_neg_with_correcting_term(ct_right);

        lwe_ciphertext_add_assign(&mut ct_left.ct, &neg_right.ct);

        ct_left.set_noise_level(
            ct_left.noise_level() + ct_right.noise_level(),
            self.max_noise_level,
        );
        ct_left.degree = Degree::new(ct_left.degree.get() + z);

        z
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn smart_sub_with_correcting_term(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> (Ciphertext, u64) {
        let SmartCleaningOperation {
            bootstrap_left,
            bootstrap_right,
        } = self
            .binary_smart_op_optimal_cleaning_strategy(
                ct_left,
                ct_right,
                |sk, ct_left, ct_right| sk.is_sub_possible(ct_left, ct_right).is_ok(),
            )
            .unwrap();

        if bootstrap_left {
            self.message_extract_assign(ct_left)
        }

        if bootstrap_right {
            self.message_extract_assign(ct_right)
        }

        self.is_sub_possible(ct_left.noise_degree(), ct_right.noise_degree())
            .unwrap();

        self.unchecked_sub_with_correcting_term(ct_left, ct_right)
    }
}
