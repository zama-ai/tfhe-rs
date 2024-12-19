use crate::shortint::ciphertext::Degree;
use crate::shortint::{Ciphertext, ServerKey};

impl ServerKey {
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 3;
    /// let clear_2 = 2;
    ///
    /// // Encrypt one message
    /// let ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_scalar_div(&ct_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / (clear_2 as u64), res);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// // Encrypt one message
    /// let ct_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_scalar_div(&ct_1, clear_2);
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

        let scalar = u64::from(scalar);
        let lookup_table = self.generate_msg_lookup_table(|x| x / scalar, ct.message_modulus);
        self.apply_lookup_table_assign(ct, &lookup_table);
        ct.degree = Degree::new(ct.degree.get() / scalar);
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
    ///     PARAM_MESSAGE_2_CARRY_2_KS_PBS, V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    /// };
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// let modulus: u8 = 2;
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_mod(&ct, modulus);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(1, dec);
    ///
    /// let (cks, sks) = gen_keys(V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// let modulus: u8 = 2;
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_mod(&ct, modulus);
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
        let modulus = u64::from(modulus);
        let acc = self.generate_msg_lookup_table(|x| x % modulus, ct.message_modulus);
        self.apply_lookup_table_assign(ct, &acc);
        ct.degree = Degree::new(modulus - 1);
    }
}
