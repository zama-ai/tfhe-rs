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
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// sks.unchecked_crt_scalar_add_assign_parallelized(&mut ctxt_1, clear_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % modulus, res);
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
}
