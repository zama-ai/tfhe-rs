use crate::integer::server_key::CheckError;
use crate::integer::{CrtCiphertext, ServerKey};

impl ServerKey {
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
