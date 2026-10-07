use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::server_key::GenericServerKey;
use crate::shortint::Ciphertext;

// # Note:
// _assign comparison operation are not made public (if they exists) as we don't think there are
// uses for them. For instance: adding has an assign variants because you can do "+" and "+="
// however, comparisons like equality do not have that, "==" does not have and "===",
// ">=" is greater of equal, not greater_assign.

impl<AP: AtomicPattern> GenericServerKey<AP> {
    /// Compute homomorphically a `>` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `>`:
    /// let ct_res = sks.greater(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(0, res);
    /// ```
    pub fn greater(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_greater(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_greater_assign(&mut result, ct_right);
        result
    }

    fn unchecked_greater_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs > rhs)
        });
    }

    /// Compute homomorphically a `>=` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `>=`:
    /// let ct_res = sks.greater_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(1, res);
    /// ```
    pub fn greater_or_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_greater_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_greater_or_equal_assign(&mut result, ct_right);
        result
    }

    fn unchecked_greater_or_equal_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs >= rhs)
        });
    }

    /// Compute homomorphically a `<` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `<`:
    /// let ct_res = sks.less(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(0, res);
    /// ```
    pub fn less(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_less(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_less_assign(&mut result, ct_right);
        result
    }

    fn unchecked_less_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs < rhs)
        });
    }

    /// Compute homomorphically a `<=` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `<=`:
    /// let ct_res = sks.less_or_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(1, res);
    /// ```
    pub fn less_or_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_less_or_equal(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
    ) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_less_or_equal_assign(&mut result, ct_right);
        result
    }

    fn unchecked_less_or_equal_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs <= rhs)
        });
    }

    /// Compute homomorphically a `==` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `==`:
    /// let ct_res = sks.equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(1, res);
    /// ```
    pub fn equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_equal_assign(&mut result, ct_right);
        result
    }

    fn unchecked_equal_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs == rhs)
        });
    }

    /// Compute homomorphically a `!=` between two ciphertexts encrypting integer values.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// let msg = 1;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a `!=`:
    /// let ct_res = sks.not_equal(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(0, res);
    /// ```
    pub fn not_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let tmp_lhs: Ciphertext;
        let tmp_rhs: Ciphertext;

        let lhs = if ct_left.carry_is_empty() {
            ct_left
        } else {
            tmp_lhs = self.message_extract(ct_left);
            &tmp_lhs
        };

        let rhs = if ct_right.carry_is_empty() {
            ct_right
        } else {
            tmp_rhs = self.message_extract(ct_right);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
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
    /// ```
    pub fn unchecked_not_equal(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_not_equal_assign(&mut result, ct_right);
        result
    }

    fn unchecked_not_equal_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |lhs, rhs| {
            u64::from(lhs != rhs)
        });
    }

    /// Equality between a ciphertext and a clear
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 == scalar as u64) as u64);
    /// ```
    pub fn scalar_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        let acc = self
            .generate_msg_lookup_table(|x| (x == scalar as u64) as u64, ct_left.message_modulus);
        self.apply_lookup_table(ct_left, &acc)
    }

    /// Difference between a ciphertext and a clear
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_not_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 != scalar as u64) as u64);
    /// ```
    pub fn scalar_not_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        let acc = self
            .generate_msg_lookup_table(|x| (x != scalar as u64) as u64, ct_left.message_modulus);
        self.apply_lookup_table(ct_left, &acc)
    }

    /// Compute homomorphically a `>=` between a ciphertext and a clear scalar.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_greater_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 >= scalar as u64) as u64);
    /// ```
    pub fn scalar_greater_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.evaluate_msg_univariate_function(ct_left, |lhs| u64::from(lhs >= scalar as u64))
    }

    /// Compute homomorphically a `<=` between a ciphertext and a clear scalar.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_less_or_equal(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 <= scalar as u64) as u64);
    /// ```
    pub fn scalar_less_or_equal(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.evaluate_msg_univariate_function(ct_left, |lhs| u64::from(lhs <= scalar as u64))
    }

    /// Compute homomorphically a `>` between a ciphertext and a clear scalar.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_greater(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 > scalar as u64) as u64);
    /// ```
    pub fn scalar_greater(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.evaluate_msg_univariate_function(ct_left, |lhs| u64::from(lhs > scalar as u64))
    }

    /// Compute homomorphically a `<` between a ciphertext and a clear scalar.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 2;
    /// let scalar = 2;
    ///
    /// // Encrypt our message
    /// let ct_left = cks.encrypt(msg_1);
    ///
    /// let ct_res = sks.scalar_less(&ct_left, scalar);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(res, (msg_1 < scalar as u64) as u64);
    /// ```
    pub fn scalar_less(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.evaluate_msg_univariate_function(ct_left, |lhs| u64::from(lhs < scalar as u64))
    }
}
