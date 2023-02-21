use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::{CiphertextBase, PBSOrderMarker};

impl ServerKey {
    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns 0!
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages
    /// let ct_1 = cks.encrypt_small(clear_1);
    /// let ct_2 = cks.encrypt_small(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_div(&ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn unchecked_div<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_div(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is _assigned_ in `ct_left`.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns 0!
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt_small(clear_1);
    /// let ct_2 = cks.encrypt_small(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn unchecked_div_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &CiphertextBase<OpOrder>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_div_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute a division between two ciphertexts.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns 0!
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt_small(clear_1);
    /// let mut ct_2 = cks.encrypt_small(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.smart_div(&mut ct_1, &mut ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn smart_div<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_div(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute a division between two ciphertexts without checks.
    ///
    /// The result is _assigned_ in `ct_left`.
    ///
    /// # Warning
    ///
    /// /!\ A division by zero returns 0!
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages
    /// let mut ct_1 = cks.encrypt_small(clear_1);
    /// let mut ct_2 = cks.encrypt_small(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_div_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_1 / clear_2, res);
    /// ```
    pub fn smart_div_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        ct_right: &mut CiphertextBase<OpOrder>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_div_assign(self, ct_left, ct_right).unwrap()
        })
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
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt one message
    /// let mut ct_1 = cks.encrypt_small(clear_1);
    ///
    /// // Compute homomorphically a multiplication
    /// let ct_res = sks.unchecked_scalar_div(&mut ct_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(clear_1 / (clear_2 as u64), res);
    /// ```
    pub fn unchecked_scalar_div<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        scalar: u8,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_div(self, ct_left, scalar).unwrap()
        })
    }

    pub fn unchecked_scalar_div_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        scalar: u8,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_scalar_div_assign(self, ct_left, scalar)
                .unwrap()
        })
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
    /// use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2, PARAM_SMALL_MESSAGE_2_CARRY_2};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
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
    /// let (cks, sks) = gen_keys(PARAM_SMALL_MESSAGE_2_CARRY_2);
    ///
    /// let mut ct = cks.encrypt_small(msg);
    ///
    /// let modulus: u8 = 2;
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_mod(&mut ct, modulus);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(1, dec);
    /// ```
    pub fn unchecked_scalar_mod<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &CiphertextBase<OpOrder>,
        modulus: u8,
    ) -> CiphertextBase<OpOrder> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_scalar_mod(self, ct_left, modulus).unwrap()
        })
    }

    pub fn unchecked_scalar_mod_assign<OpOrder: PBSOrderMarker>(
        &self,
        ct_left: &mut CiphertextBase<OpOrder>,
        modulus: u8,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_scalar_mod_assign(self, ct_left, modulus)
                .unwrap()
        })
    }
}
