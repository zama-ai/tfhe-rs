use crate::shortint::ciphertext::Degree;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
    /// Compute a division between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
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
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.div(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.div(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn div(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.div_assign(&mut ct_res, ct_right);
        ct_res
    }

    /// Compute a division between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
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
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn div_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
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

        self.unchecked_div_assign(ct_left, rhs);
    }

    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_div(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_div(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn unchecked_div(&self, ct_left: &Ciphertext, ct_right: &Ciphertext) -> Ciphertext {
        let mut result = ct_left.clone();
        self.unchecked_div_assign(&mut result, ct_right);
        result
    }

    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is _assigned_ in `ct_left`.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn unchecked_div_assign(&self, ct_left: &mut Ciphertext, ct_right: &Ciphertext) {
        let value_on_div_by_zero = (ct_left.message_modulus.0 - 1) as u64;
        self.unchecked_evaluate_bivariate_function_assign(ct_left, ct_right, |x, y| {
            safe_division(x, y, value_on_div_by_zero)
        });
    }

    /// Compute a division between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 1;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_div(&mut ct_1, &mut ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_div(&mut ct_1, &mut ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn smart_div(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) -> Ciphertext {
        let value_on_div_by_zero = (ct_left.message_modulus.0 - 1) as u64;
        self.smart_evaluate_bivariate_function(ct_left, ct_right, |x, y| {
            safe_division(x, y, value_on_div_by_zero)
        })
    }

    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is _assigned_ in `ct_left`.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns the input ciphertext maximum message value! For 2 bits of
    /// message it will therefore return 3.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt(clear_1);
    /// let mut ct_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn smart_div_assign(&self, ct_left: &mut Ciphertext, ct_right: &mut Ciphertext) {
        let value_on_div_by_zero = (ct_left.message_modulus.0 - 1) as u64;
        self.smart_evaluate_bivariate_function_assign(ct_left, ct_right, |x, y| {
            safe_division(x, y, value_on_div_by_zero)
        });
    }

    /// Alias to [`unchecked_scalar_div`](`Self::unchecked_scalar_div`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Panics
    ///
    /// This function will panic if `scalar == 0`.
    pub fn scalar_div(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.unchecked_scalar_div(ct_left, scalar)
    }

    /// Alias to [`unchecked_scalar_div_assign`](`Self::unchecked_scalar_div_assign`) provided for
    /// convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Panics
    ///
    /// This function will panic if `scalar == 0`.
    pub fn scalar_div_assign(&self, ct_left: &mut Ciphertext, scalar: u8) {
        self.unchecked_scalar_div_assign(ct_left, scalar);
    }

    /// Compute a division of a ciphertext by a scalar without checks.
    ///
    /// # Panics
    ///
    /// This function will panic if `scalar == 0`.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt one message
    /// let mut ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_scalar_div(&mut ct_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / (clear_2 as u64), res);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// // Encrypt one message
    /// let mut ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_scalar_div(&mut ct_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / (clear_2 as u64), res);
    /// ```
    pub fn unchecked_scalar_div(&self, ct: &Ciphertext, scalar: u8) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_scalar_div_assign(&mut result, scalar);
        result
    }

    pub fn unchecked_scalar_div_assign(&self, ct: &mut Ciphertext, scalar: u8) {
        assert_ne!(scalar, 0, "attempt to divide by zero");

        let lookup_table =
            self.generate_msg_lookup_table(|x| x / (scalar as u64), ct.message_modulus);
        self.apply_lookup_table_assign(ct, &lookup_table);
        ct.degree = Degree::new(ct.degree.get() / scalar as usize);
    }

    /// Alias to [`unchecked_scalar_mod`](`Self::unchecked_scalar_mod`) provided for convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Panics
    ///
    /// This function will panic if `scalar == 0`.
    pub fn scalar_mod(&self, ct_left: &Ciphertext, scalar: u8) -> Ciphertext {
        self.unchecked_scalar_mod(ct_left, scalar)
    }

    /// Alias to [`unchecked_scalar_mod_assign`](`Self::unchecked_scalar_mod_assign`) provided for
    /// convenience
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertext carries are empty and clears them if it's not the case and
    /// the operation requires it. It outputs a ciphertext whose carry is always empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Panics
    ///
    /// This function will panic if `scalar == 0`.
    pub fn scalar_mod_assign(&self, ct_left: &mut Ciphertext, scalar: u8) {
        self.unchecked_scalar_mod_assign(ct_left, scalar);
    }

    /// Compute homomorphically a modular reduction without checks.
    ///
    /// # Panics
    ///
    /// This function will panic if `modulus == 0`.
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
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let modulus: u8 = 2;
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_mod(&mut ct, modulus);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(1, dec);
    ///
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_PBS_KS);
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let modulus: u8 = 2;
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_mod(&mut ct, modulus);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(1, dec);
    /// ```
    pub fn unchecked_scalar_mod(&self, ct: &Ciphertext, modulus: u8) -> Ciphertext {
        let mut result = ct.clone();
        self.unchecked_scalar_mod_assign(&mut result, modulus);
        result
    }

    pub fn unchecked_scalar_mod_assign(&self, ct: &mut Ciphertext, modulus: u8) {
        assert_ne!(modulus, 0);
        let acc = self.generate_msg_lookup_table(|x| x % modulus as u64, ct.message_modulus);
        self.apply_lookup_table_assign(ct, &acc);
        ct.degree = Degree::new(modulus as usize - 1);
    }
}

// Specific division function returning value_on_div_by_zero in case of a division by 0
pub(crate) fn safe_division(x: u64, y: u64, value_on_div_by_zero: u64) -> u64 {
    if y == 0 {
        value_on_div_by_zero
    } else {
        x / y
    }
}
