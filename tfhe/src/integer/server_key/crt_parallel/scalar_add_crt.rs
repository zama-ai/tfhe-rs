use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::{CrtCiphertext, ServerKey};
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically an addition between a scalar and a ciphertext.
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.unchecked_crt_scalar_add_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_scalar_add_parallelized(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        let mut result = ct.clone();
        self.unchecked_crt_scalar_add_assign_parallelized(&mut result, scalar);
        result
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    pub fn unchecked_crt_scalar_add_assign_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) {
        //Add the crt representation of the scalar to the ciphertext
        ct.blocks
            .par_iter_mut()
            .zip(ct.moduli.par_iter())
            .for_each(|(ct_i, mod_i)| {
                let scalar_i = scalar % mod_i;
                self.key.unchecked_scalar_add_assign(ct_i, scalar_i as u8);
            });
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.checked_crt_scalar_add_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_crt_scalar_add_parallelized(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<CrtCiphertext, CheckError> {
        if self.is_crt_scalar_add_possible(ct, scalar) {
            Ok(self.unchecked_crt_scalar_add_parallelized(ct, scalar))
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    pub fn checked_crt_scalar_add_assign_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        if self.is_crt_scalar_add_possible(ct, scalar) {
            self.unchecked_crt_scalar_add_assign_parallelized(ct, scalar);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// let ctxt = sks.smart_crt_scalar_add_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn smart_crt_scalar_add_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        if !self.is_crt_scalar_add_possible(ct, scalar) {
            self.full_extract_message_assign_parallelized(ct);
        }

        let mut ct = ct.clone();
        self.unchecked_crt_scalar_add_assign_parallelized(&mut ct, scalar);
        ct
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// let basis = vec![2, 3, 5];
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt_crt(clear_1, basis.clone());
    ///
    /// sks.smart_crt_scalar_add_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn smart_crt_scalar_add_assign_parallelized(&self, ct: &mut CrtCiphertext, scalar: u64) {
        if !self.is_crt_scalar_add_possible(ct, scalar) {
            self.full_extract_message_assign_parallelized(ct);
        }
        self.unchecked_crt_scalar_add_assign_parallelized(ct, scalar);
    }
}
