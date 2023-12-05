use crate::integer::server_key::CheckError;
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
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.unchecked_crt_scalar_sub_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
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
            self.key.unchecked_scalar_add_assign(ct_i, neg_scalar as u8);
        }
    }

    /// Verifies if the subtraction of a ciphertext by scalar can be computed.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// let basis = vec![2, 3, 5];
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.is_crt_scalar_sub_possible(&mut ctxt_1, clear_2)
    ///     .unwrap();
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// ```
    pub fn is_crt_scalar_sub_possible(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        for (ct_i, mod_i) in ct.blocks.iter().zip(ct.moduli.iter()) {
            let neg_scalar = (mod_i - scalar % mod_i) % mod_i;

            self.key
                .is_scalar_add_possible(ct_i.noise_degree(), neg_scalar as u8)?;
        }
        Ok(())
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 8;
    ///
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// let ct_res = sks.checked_crt_scalar_sub(&mut ctxt_1, clear_2)?;
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 - clear_2) % modulus, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_sub(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<CrtCiphertext, CheckError> {
        self.is_crt_scalar_sub_possible(ct, scalar)?;
        Ok(self.unchecked_crt_scalar_sub(ct, scalar))
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    ///
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.checked_crt_scalar_sub_assign(&mut ctxt_1, clear_2)?;
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_sub_assign(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        self.is_crt_scalar_sub_possible(ct, scalar)?;
        self.unchecked_crt_scalar_sub_assign(ct, scalar);
        Ok(())
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.smart_crt_scalar_sub_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_scalar_sub(&self, ct: &mut CrtCiphertext, scalar: u64) -> CrtCiphertext {
        if self.is_crt_scalar_sub_possible(ct, scalar).is_err() {
            self.full_extract_message_assign(ct);
        }
        self.is_crt_scalar_sub_possible(ct, scalar).unwrap();

        self.unchecked_crt_scalar_sub(ct, scalar)
    }

    pub fn smart_crt_scalar_sub_assign(&self, ct: &mut CrtCiphertext, scalar: u64) {
        if self.is_crt_scalar_sub_possible(ct, scalar).is_err() {
            self.full_extract_message_assign(ct);
        }
        self.is_crt_scalar_sub_possible(ct, scalar).unwrap();

        self.unchecked_crt_scalar_sub_assign(ct, scalar);
    }
}
