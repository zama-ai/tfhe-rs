use super::ServerKey;
use crate::core_crypto::algorithms::lwe_ciphertext_opposite_assign;
use crate::shortint::ciphertext::Degree;
use crate::shortint::{CheckError, Ciphertext};

impl ServerKey {
    /// Compute homomorphically an AND between two ciphertexts encrypting integer values.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.bitand(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.bitand(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg, res);
    /// ```
    pub fn bitand(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.bitand_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute homomorphically an AND between two ciphertexts encrypting integer values.
    ///
    /// The result is stored in the `ct_left` cipher text.
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
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an AND:
    /// sks.bitand_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 & msg1) % modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an AND:
    /// sks.bitand_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 & msg1) % modulus, res);
    /// ```
    pub fn bitand_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
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

        self.unchecked_bitand_assign(ct_left, rhs);
    }

    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(&mut result, ct_right);
        result
    }

    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        let new_degree = ct_left.degree.after_bitand(ct_right.degree);
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs & rhs);
        ct_left.degree = new_degree;
    }

    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.checked_bitand(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.checked_bitand(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg);
    /// ```
    pub fn checked_bitand(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        let ct_result = self.unchecked_bitand(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Compute bitwise AND between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// sks.checked_bitand_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an AND:
    /// sks.checked_bitand_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg);
    /// ```
    pub fn checked_bitand_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        self.unchecked_bitand_assign(ct_left, ct_right);
        Ok(())
    }

    /// Compute homomorphically an AND between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// assert_eq!(msg, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// assert_eq!(msg, res);
    /// ```
    pub fn smart_bitand(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        self.smart_evaluate_bivariate_function(ct_left, ct_right, |lhs, rhs| lhs & rhs)
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs & rhs);
    }

    /// Compute homomorphically an XOR between two ciphertexts encrypting integer values.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a XOR:
    /// let ct_res = sks.bitxor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(0, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a XOR:
    /// let ct_res = sks.bitxor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(0, res);
    /// ```
    pub fn bitxor(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.bitxor_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute homomorphically a XOR between two ciphertexts encrypting integer values.
    ///
    /// The result is stored in the `ct_left` cipher text.
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
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a XOR:
    /// sks.bitxor_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 ^ msg1) % modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a XOR:
    /// sks.bitxor_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 ^ msg1) % modulus, res);
    /// ```
    pub fn bitxor_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
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

        self.unchecked_bitxor_assign(ct_left, rhs);
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(&mut result, ct_right);
        result
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 2;
    /// let clear_2 = 0;
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt(clear_2);
    ///
    /// sks.unchecked_bitxor_assign(&mut ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_1 ^ clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages
    /// let mut ct_left = cks.encrypt(clear_1);
    /// let ct_right = cks.encrypt(clear_2);
    ///
    /// sks.unchecked_bitxor_assign(&mut ct_left, &ct_right);
    ///
    /// let res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_1 ^ clear_2, res);
    /// ```
    pub fn unchecked_bitxor_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        let new_degree = ct_left.degree.after_bitxor(ct_right.degree);
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs ^ rhs);
        ct_left.degree = new_degree;
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a xor:
    /// let ct_res = sks.checked_bitxor(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 0);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a xor:
    /// let ct_res = sks.checked_bitxor(&ct1, &ct2).unwrap();
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, 0);
    /// ```
    pub fn checked_bitxor(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        let ct_result = self.unchecked_bitxor(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Compute bitwise XOR between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a xor:
    /// sks.checked_bitxor_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, 0);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a xor:
    /// sks.checked_bitxor_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, 0);
    /// ```
    pub fn checked_bitxor_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        self.unchecked_bitxor_assign(ct_left, ct_right);
        Ok(())
    }

    /// Compute homomorphically an XOR between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// assert_eq!(0, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// assert_eq!(0, res);
    /// ```
    pub fn smart_bitxor(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        self.smart_evaluate_bivariate_function(ct_left, ct_right, |lhs, rhs| lhs ^ rhs)
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs ^ rhs);
    }

    /// Compute homomorphically an OR between two ciphertexts encrypting integer values.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.bitor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.bitor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg, res);
    /// ```
    pub fn bitor(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.bitor_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute homomorphically an OR between two ciphertexts encrypting integer values.
    ///
    /// The result is stored in the `ct_left` cipher text.
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
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an OR:
    /// sks.bitor_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 | msg1) % modulus, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// let mut ct1 = cks.unchecked_encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an OR:
    /// sks.bitor_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct1);
    ///
    /// assert_eq!((msg2 | msg1) % modulus, res);
    /// ```
    pub fn bitor_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
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

        self.unchecked_bitor_assign(ct_left, rhs);
    }

    /// Compute bitwise OR between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(&mut result, ct_right);
        result
    }

    /// Compute bitwise OR between two ciphertexts.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
        let resulting_degree = ct_left.degree.after_bitor(ct_right.degree);
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs | rhs);
        ct_left.degree = resulting_degree;
    }

    /// Compute bitwise OR between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a or:
    /// let ct_res = sks.checked_bitor(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a or:
    /// let ct_res = sks.checked_bitor(&ct1, &ct2).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_res, msg);
    /// ```
    pub fn checked_bitor(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        let ct_result = self.unchecked_bitor(ct_left, ct_right);
        Ok(ct_result)
    }

    /// Compute bitwise OR between two ciphertexts without checks.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an or:
    /// sks.checked_bitor_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
    /// let mut ct_left = cks.encrypt(msg);
    /// let ct_right = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an or:
    /// sks.checked_bitor_assign(&mut ct_left, &ct_right).unwrap();
    ///
    /// let clear_res = cks.decrypt(&ct_left);
    /// assert_eq!(clear_res, msg);
    /// ```
    pub fn checked_bitor_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<(), CheckError> {
        self.is_functional_bivariate_pbs_possible(
            ct_left.noise_degree(),
            ct_right.noise_degree(),
            None,
        )?;
        self.unchecked_bitor_assign(ct_left, ct_right);
        Ok(())
    }

    /// Compute homomorphically an OR between two ciphertexts encrypting integer values.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
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
    /// assert_eq!(msg, res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
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
    /// assert_eq!(msg, res);
    /// ```
    pub fn smart_bitor(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        self.smart_evaluate_bivariate_function(ct_left, ct_right, |lhs, rhs| lhs | rhs)
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
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let modulus = 4;
    ///
    /// let msg1 = 15;
    /// let msg2 = 3;
    ///
    /// // Encrypt two messages:
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
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt two messages:
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
        self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| lhs | rhs);
    }

    pub fn bitnot_assign(&self, ct: &mut Ciphertext) {
        assert!(ct.message_modulus.0.is_power_of_two());
        if !ct.carry_is_empty() {
            self.message_extract_assign(ct);
        }
        // We do (-ciphertext) + (msg_mod -1) as it allows to avoid an allocation
        lwe_ciphertext_opposite_assign(&mut ct.ct);
        self.unchecked_scalar_add_assign(ct, ct.message_modulus.0 as u8 - 1);
        ct.degree = Degree::new(ct.message_modulus.0 - 1)
    }

    pub fn bitnot(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.bitnot_assign(&mut result);
        result
    }
}
