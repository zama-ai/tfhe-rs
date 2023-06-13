use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::Ciphertext;

// # Note:
// _assign comparison operation are not made public (if they exists) as we don't think there are
// uses for them. For instance: adding has an assign variants because you can do "+" and "+="
// however, comparisons like equality do not have that, "==" does not have and "===",
// ">=" is greater of equal, not greater_assign.

impl ServerKey {
    /// Compute homomorphically a `>` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.greater(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg > msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.greater(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg > msg) as u64, res);
    /// ```
    pub fn greater(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_greater(lhs, rhs)
    }

    /// Implement the "greater" (`>`) operator between two ciphertexts without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_greater(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 > msg_2) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_greater(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 > msg_2) as u64, res);
    /// ```
    pub fn unchecked_greater(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_greater(self, ct_left, ct_right).unwrap()
        })
    }

    /// Implement the "greater" (`>`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_greater(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 > msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_greater(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 > msg_2) as u64, clear_res);
    /// ```
    pub fn checked_greater(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_greater(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `>` between two ciphertexts encrypting integer values.
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are full,
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_greater(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg > msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_greater(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg > msg) as u64, res);
    /// ```
    pub fn smart_greater(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_greater(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a `>=` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.greater_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg >= msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.greater_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg >= msg) as u64, res);
    /// ```
    pub fn greater_or_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_greater_or_equal(lhs, rhs)
    }

    /// Implement the "greater or equal" (`>=`) operator between two ciphertexts without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_greater_or_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 >= msg_2) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_greater_or_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 >= msg_2) as u64, res);
    /// ```
    pub fn unchecked_greater_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_greater_or_equal(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute homomorphically a `>=` between two ciphertexts encrypting integer values.
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are full,
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_greater_or_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg >= msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_greater_or_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg >= msg) as u64, res);
    /// ```
    pub fn smart_greater_or_equal(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_greater_or_equal(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Implement the "greater or equal" (`>=`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_greater_or_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 >= msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_greater_or_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 >= msg_2) as u64, clear_res);
    /// ```
    pub fn checked_greater_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_greater_or_equal(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `<` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.less(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg < msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.less(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg < msg) as u64, res);
    /// ```
    pub fn less(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_less(lhs, rhs)
    }

    /// Implement the "less" (`<`) operator between two ciphertexts without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// // Do the comparison
    /// let ct_res = sks.unchecked_less(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 < msg_2) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// // Do the comparison
    /// let ct_res = sks.unchecked_less(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 < msg_2) as u64, res);
    /// ```
    pub fn unchecked_less(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_less(self, ct_left, ct_right).unwrap()
        })
    }

    /// Implement the "less" (`<`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_less(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 < msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_less(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 < msg_2) as u64, clear_res);
    /// ```
    pub fn checked_less(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_less(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `<` between two ciphertexts encrypting integer values.
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are full,
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_less(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg < msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_less(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg < msg) as u64, res);
    /// ```
    pub fn smart_less(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_less(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a `<=` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.less_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg <= msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.less_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg <= msg) as u64, res);
    /// ```
    pub fn less_or_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_less_or_equal(lhs, rhs)
    }

    /// Implement the "less or equal" (`<=`) between two ciphertexts operator without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_less_or_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 <= msg_2) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_less_or_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg_1 <= msg_2) as u64, res);
    /// ```
    pub fn unchecked_less_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_less_or_equal(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Implement the "less or equal" (`<=`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_less_or_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 <= msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_less_or_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 <= msg_2) as u64, clear_res);
    /// ```
    pub fn checked_less_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_less(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `<=` between two ciphertexts encrypting integer values.
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are full,
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_less_or_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg <= msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_less_or_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg <= msg) as u64, res);
    /// ```
    pub fn smart_less_or_equal(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_less_or_equal(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a `==` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg == msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg == msg) as u64, res);
    /// ```
    pub fn equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_equal(lhs, rhs)
    }

    /// Implement the "equal" operator (`==`) between two ciphertexts without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, 1);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, 1);
    /// ```
    pub fn unchecked_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_equal(self, ct_left, ct_right).unwrap()
        })
    }

    /// Implement the "equal" (`==`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 == msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 == msg_2) as u64, clear_res);
    /// ```
    pub fn checked_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_equal(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `==` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg == msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg == msg) as u64, res);
    /// ```
    pub fn smart_equal(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_equal(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a `!=` between two ciphertexts encrypting integer values.
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.not_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg != msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.not_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg != msg) as u64, res);
    /// ```
    pub fn not_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.clear_carry(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.clear_carry(ct_right);
            &tmp_rhs
        };

        self.unchecked_not_equal(lhs, rhs)
    }

    /// Implement the "not equal" operator (`!=`) between two ciphertexts without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_not_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, 1);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let ct_res = sks.unchecked_not_equal(&ct_left, &ct_right);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, 1);
    /// ```
    pub fn unchecked_not_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_not_equal(self, ct_left, ct_right).unwrap()
        })
    }

    /// Implement the "not equal" (`!=`) operator between two ciphertexts with checks.
    ///
    /// If the operation can be performed, the result is returned in a _new_ ciphertext.
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
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 1;
    /// let msg_2 = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_not_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 != msg_2) as u64, clear_res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let ct_left = cks.encrypt(msg_1);
    /// let ct_right = cks.encrypt(msg_2);
    ///
    /// let res = sks.checked_not_equal(&ct_left, &ct_right);
    ///
    /// assert!(res.is_ok());
    /// let res = res.unwrap();
    ///
    /// let clear_res = cks.decrypt(&res);
    /// assert_eq!((msg_1 != msg_2) as u64, clear_res);
    /// ```
    pub fn checked_not_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Result<Ciphertext, CheckError> {
        if self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            Ok(self.unchecked_not_equal(ct_left, ct_right))
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a `!=` between two ciphertexts encrypting integer values.
    ///
    /// This checks that the operation is possible. In the case where the carry buffers are full,
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
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_not_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg != msg) as u64, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages:
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.smart_not_equal(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!((msg != msg) as u64, res);
    /// ```
    pub fn smart_not_equal(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
    ) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_not_equal(self, ct_left, ct_right).unwrap()
        })
    }

    /// Implement the "equal" operator (`==`) between a ciphertext and a scalar without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 == scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 == scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_equal(self, ct_left, scalar).unwrap()
        })
    }

    /// Alias of [`smart_scalar_equal`](`Self::smart_scalar_equal`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_equal(ct_left, scalar)
    }

    /// Implement the "not equal" operator (`!=`) between a ciphertext and a scalar without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_not_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 != scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_not_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 != scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_not_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_scalar_not_equal(self, ct_left, scalar)
                .unwrap()
        })
    }

    /// Alias of [`smart_scalar_not_equal`](`Self::smart_scalar_not_equal`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_not_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_not_equal(ct_left, scalar)
    }

    /// Implement the "greater or equal" operator (`>=`) between a ciphertext and a scalar without
    /// checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_greater_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 >= scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_greater_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 >= scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_greater_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_scalar_greater_or_equal(self, ct_left, scalar)
                .unwrap()
        })
    }

    /// Alias of [`smart_scalar_greater_or_equal`](`Self::smart_scalar_greater_or_equal`) provided
    /// for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_greater_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_greater_or_equal(ct_left, scalar)
    }

    /// Implement the "less or equal" operator (`<=`) between a ciphertext and a scalar without
    /// checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_less_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 <= scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_less_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 <= scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_less_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .smart_scalar_less_or_equal(self, ct_left, scalar)
                .unwrap()
        })
    }

    /// Alias of [`smart_scalar_less_or_equal`](`Self::smart_scalar_less_or_equal`) provided for
    /// convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_less_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_less_or_equal(ct_left, scalar)
    }

    /// Implement the "greater" operator (`>`) between a ciphertext and a scalar without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_greater(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 > scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_greater(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 > scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_greater(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_greater(self, ct_left, scalar).unwrap()
        })
    }

    /// Alias of [`smart_scalar_greater`](`Self::smart_scalar_greater`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_greater(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_greater(ct_left, scalar)
    }

    /// Implement the "less" operator (`<`) between a ciphertext and a scalar without checks.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_less(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 < scalar as u64) as u64);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.smart_scalar_less(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 < scalar as u64) as u64);
    /// ```
    pub fn smart_scalar_less(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_scalar_less(self, ct_left, scalar).unwrap()
        })
    }

    /// Alias of [`smart_scalar_less`](`Self::smart_scalar_less`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    pub fn scalar_less(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.smart_scalar_less(ct_left, scalar)
    }
}
