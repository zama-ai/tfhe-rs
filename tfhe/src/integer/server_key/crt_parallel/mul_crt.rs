use crate::integer::ciphertext::CrtCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer
    /// values in the CRT decomposition.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    /// let size = 3;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 29;
    /// let clear_2 = 23;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_crt_mul_assign_parallelized(&mut ctxt_1, &ctxt_2);
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn unchecked_crt_mul_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(ct_right.blocks.par_iter())
            .for_each(|(ct_left, ct_right)| {
                if ct_left.message_modulus.0 <= ct_left.carry_modulus.0 {
                    self.key.unchecked_mul_lsb_assign(ct_left, ct_right);
                } else {
                    self.key
                        .unchecked_mul_lsb_small_carry_assign(ct_left, ct_right);
                }
            });
    }

    pub fn unchecked_crt_mul_parallelized(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_crt_mul_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }

    /// Computes homomorphically a multiplication between two ciphertexts encrypting integer
    /// values in the CRT decomposition.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 29;
    /// let clear_2 = 29;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.smart_crt_mul_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_mul_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(ct_right.blocks.par_iter_mut())
            .for_each(|(block_left, block_right)| {
                self.key.smart_mul_lsb_assign(block_left, block_right);
            });
    }

    // by convention smart operations take mut refs to their inputs, even if they do not modify them
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_crt_mul_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.smart_crt_mul_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }
}
