use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::{CrtCiphertext, ServerKey};

impl ServerKey {
    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.unchecked_crt_scalar_sub_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_scalar_sub(&self, ct: &CrtCiphertext, scalar: u64) -> CrtCiphertext {
        let mut result = ct.clone();
        self.unchecked_crt_scalar_sub_assign(&mut result, scalar);
        result
    }

    pub fn unchecked_crt_scalar_sub_assign(&self, ct: &mut CrtCiphertext, scalar: u64) {
        //Put each decomposition into a new ciphertext
        for (ct_i, mod_i) in ct.blocks.iter_mut().zip(ct.moduli.iter()) {
            let neg_scalar = (mod_i - scalar % mod_i) % mod_i;
            self.key
                .unchecked_scalar_add_assign_crt(ct_i, neg_scalar as u8);
        }
    }

    /// Verifies if the subtraction of a ciphertext by scalar can be computed.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// let bit = sks.is_crt_scalar_sub_possible(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!(true, bit);
    /// ```
    pub fn is_crt_scalar_sub_possible(&self, ct: &CrtCiphertext, scalar: u64) -> bool {
        for (ct_i, mod_i) in ct.blocks.iter().zip(ct.moduli.iter()) {
            let neg_scalar = (mod_i - scalar % mod_i) % mod_i;

            if !self.key.is_scalar_add_possible(ct_i, neg_scalar as u8) {
                return false;
            }
        }
        true
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 8;
    /// let basis = vec![2, 3, 5];
    ///
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// let ct_res = sks.checked_crt_scalar_sub(&mut ctxt_1, clear_2)?;
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt_crt(&ct_res);
    /// assert_eq!((clear_1 - clear_2) % 30, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_sub(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<CrtCiphertext, CheckError> {
        if self.is_crt_scalar_sub_possible(ct, scalar) {
            Ok(self.unchecked_crt_scalar_sub(ct, scalar))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// let basis = vec![2, 3, 5];
    ///
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.checked_crt_scalar_sub_assign(&mut ctxt_1, clear_2)?;
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % 30, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_sub_assign(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        if self.is_crt_scalar_sub_possible(ct, scalar) {
            self.unchecked_crt_scalar_sub_assign(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.smart_crt_scalar_sub_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % 30, res);
    /// ```
    pub fn smart_crt_scalar_sub(&self, ct: &mut CrtCiphertext, scalar: u64) -> CrtCiphertext {
        if !self.is_crt_scalar_sub_possible(ct, scalar) {
            self.full_extract_message_assign(ct);
        }

        self.unchecked_crt_scalar_sub(ct, scalar)
    }

    pub fn smart_crt_scalar_sub_assign(&self, ct: &mut CrtCiphertext, scalar: u64) {
        if !self.is_crt_scalar_sub_possible(ct, scalar) {
            self.full_extract_message_assign(ct);
        }

        self.unchecked_crt_scalar_sub_assign(ct, scalar);
    }
}
