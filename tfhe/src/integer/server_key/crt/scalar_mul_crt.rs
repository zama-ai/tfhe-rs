use crate::integer::server_key::CheckError;
use crate::integer::{CrtCiphertext, ServerKey};

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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 2;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.unchecked_crt_scalar_mul_assign(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_scalar_mul(&self, ctxt: &CrtCiphertext, scalar: u64) -> CrtCiphertext {
        let mut ct_result = ctxt.clone();
        self.unchecked_crt_scalar_mul_assign(&mut ct_result, scalar);

        ct_result
    }

    pub fn unchecked_crt_scalar_mul_assign(&self, ctxt: &mut CrtCiphertext, scalar: u64) {
        for (ct_i, mod_i) in ctxt.blocks.iter_mut().zip(ctxt.moduli.iter()) {
            let scalar_i = (scalar % mod_i) as u8;
            if self
                .key
                .max_degree
                .validate(ct_i.degree * u64::from(scalar_i))
                .is_ok()
                && self
                    .key
                    .max_noise_level
                    .validate(ct_i.noise_level() * scalar)
                    .is_ok()
            {
                self.key.unchecked_scalar_mul_assign(ct_i, scalar_i);
            } else {
                self.key
                    .unchecked_scalar_mul_lsb_small_carry_modulus_assign(ct_i, scalar_i);
            }
        }
    }

    ///Verifies if ct1 can be multiplied by scalar.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 2;
    /// // Encrypt two messages
    /// let ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.is_crt_scalar_mul_possible(&ctxt_1, clear_2).unwrap();
    /// ```
    pub fn is_crt_scalar_mul_possible(
        &self,
        ctxt: &CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        for (ct_i, mod_i) in ctxt.blocks.iter().zip(ctxt.moduli.iter()) {
            self.key
                .is_scalar_mul_possible(ct_i.noise_degree(), (scalar % mod_i) as u8)?;
        }
        Ok(())
    }

    pub fn is_crt_small_scalar_mul_possible(
        &self,
        ctxt: &CrtCiphertext,
        scalar: u64,
    ) -> Result<(), CheckError> {
        for ct_i in ctxt.blocks.iter() {
            self.key
                .is_scalar_mul_possible(ct_i.noise_degree(), scalar as u8)?;
        }
        Ok(())
    }
}
