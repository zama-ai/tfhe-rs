use crate::integer::server_key::CheckError;
use crate::integer::{CrtCiphertext, ServerKey};
use rayon::prelude::*;

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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.unchecked_crt_scalar_sub_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_scalar_sub_parallelized(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        let mut result = ct.clone();
        self.unchecked_crt_scalar_sub_assign_parallelized(&mut result, scalar);
        result
    }

    pub fn unchecked_crt_scalar_sub_assign_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) {
        //Put each decomposition into a new ciphertext
        ct.blocks
            .par_iter_mut()
            .zip(ct.moduli.par_iter())
            .for_each(|(ct_i, mod_i)| {
                let neg_scalar = (mod_i - scalar % mod_i) % mod_i;
                self.key.unchecked_scalar_add_assign(ct_i, neg_scalar as u8);
            });
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 8;
    ///
    /// let ctxt_1 = cks.encrypt(clear_1);
    ///
    /// let ct_res = sks
    ///     .checked_crt_scalar_sub_parallelized(&ctxt_1, clear_2)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!((clear_1 - clear_2) % modulus, dec);
    /// ```
    pub fn checked_crt_scalar_sub_parallelized(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<CrtCiphertext, CheckError> {
        self.is_crt_scalar_sub_possible(ct, scalar)?;
        Ok(self.unchecked_crt_scalar_sub_parallelized(ct, scalar))
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    ///
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.checked_crt_scalar_sub_assign_parallelized(&mut ctxt_1, clear_2)
    ///     .unwrap();
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, dec);
    /// ```
    pub fn checked_crt_scalar_sub_assign_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        self.is_crt_scalar_sub_possible(ct, scalar)?;
        self.unchecked_crt_scalar_sub_assign_parallelized(ct, scalar);
        Ok(())
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 7;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.smart_crt_scalar_sub_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 - clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_scalar_sub_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        if self.is_crt_scalar_sub_possible(ct, scalar).is_err() {
            self.full_extract_message_assign_parallelized(ct);
        }

        self.is_crt_scalar_sub_possible(ct, scalar).unwrap();
        self.unchecked_crt_scalar_sub_parallelized(ct, scalar)
    }

    pub fn smart_crt_scalar_sub_assign_parallelized(&self, ct: &mut CrtCiphertext, scalar: u64) {
        if self.is_crt_scalar_sub_possible(ct, scalar).is_err() {
            self.full_extract_message_assign_parallelized(ct);
        }

        self.is_crt_scalar_sub_possible(ct, scalar).unwrap();

        self.unchecked_crt_scalar_sub_assign_parallelized(ct, scalar);
    }
}
