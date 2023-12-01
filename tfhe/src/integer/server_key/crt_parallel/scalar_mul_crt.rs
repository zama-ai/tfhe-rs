use crate::integer::server_key::CheckError;
use crate::integer::{CrtCiphertext, ServerKey};
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
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
    /// let clear_2 = 2;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.unchecked_crt_scalar_mul_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_scalar_mul_parallelized(
        &self,
        ctxt: &CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_crt_scalar_mul_assign_parallelized(&mut ct_result, scalar);
        ct_result
    }

    pub fn unchecked_crt_scalar_mul_assign_parallelized(
        &self,
        ctxt: &mut CrtCiphertext,
        scalar: u64,
    ) {
        ctxt.blocks
            .par_iter_mut()
            .zip(ctxt.moduli.par_iter())
            .for_each(|(ct_i, mod_i)| {
                let scalar_i = (scalar % mod_i) as u8;
                if self
                    .key
                    .max_degree
                    .validate(ct_i.degree * scalar_i as usize)
                    .is_ok()
                {
                    self.key.unchecked_scalar_mul_assign(ct_i, scalar_i);
                } else {
                    self.key
                        .unchecked_scalar_mul_lsb_small_carry_modulus_assign(ct_i, scalar_i);
                }
            });
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 2;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.checked_crt_scalar_mul_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn checked_crt_scalar_mul_parallelized(
        &self,
        ct: &CrtCiphertext,
        scalar: u64,
    ) -> Result<CrtCiphertext, CheckError> {
        let mut ct_result = ct.clone();

        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        self.is_crt_scalar_mul_possible(ct, scalar)?;
        ct_result = self.unchecked_crt_scalar_mul(&ct_result, scalar);

        Ok(ct_result)
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is assigned to the ciphertext given
    /// as parameter.
    /// Otherwise a [CheckError] is returned.
    pub fn checked_crt_scalar_mul_assign_parallelized(
        &self,
        ct: &mut CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        // If the ciphertext cannot be multiplied without exceeding the capacity of a ciphertext
        self.is_crt_scalar_mul_possible(ct, scalar)?;
        self.unchecked_crt_scalar_mul_assign_parallelized(ct, scalar);
        Ok(())
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar value shall fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    /// the scalar should fit in 2 bits.
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
    /// let clear_2 = 14;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// let ctxt = sks.smart_crt_scalar_mul_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_scalar_mul_parallelized(
        &self,
        ctxt: &mut CrtCiphertext,
        scalar: u64,
    ) -> CrtCiphertext {
        if self.is_crt_scalar_mul_possible(ctxt, scalar).is_err() {
            self.full_extract_message_assign_parallelized(ctxt);
        }
        self.is_crt_scalar_mul_possible(ctxt, scalar).unwrap();
        self.unchecked_crt_scalar_mul(ctxt, scalar)
    }

    /// Computes homomorphically a multiplication between a scalar and a ciphertext.
    ///
    /// `small` means the scalar shall value fit in a __shortint block__.
    /// For example, if the parameters are PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    /// the scalar should fit in 2 bits.
    ///
    /// The result is assigned to the input ciphertext
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
    /// let clear_2 = 14;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.smart_crt_scalar_mul_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_scalar_mul_assign_parallelized(&self, ctxt: &mut CrtCiphertext, scalar: u64) {
        if self.is_crt_small_scalar_mul_possible(ctxt, scalar).is_err() {
            self.full_extract_message_assign_parallelized(ctxt);
        }
        self.is_crt_scalar_mul_possible(ctxt, scalar).unwrap();

        self.unchecked_crt_scalar_mul_assign_parallelized(ctxt, scalar);
    }
}
