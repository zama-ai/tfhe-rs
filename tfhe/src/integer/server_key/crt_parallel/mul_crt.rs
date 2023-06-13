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
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_mul_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(&ct_right.blocks)
            .for_each(|(ct_left, ct_right)| {
                self.key.unchecked_mul_lsb_assign(ct_left, ct_right);
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
    /// assert_eq!((clear_1 * clear_2) % 30, res);
    /// ```
    pub fn smart_crt_mul_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(&mut ct_right.blocks)
            .for_each(|(block_left, block_right)| {
                self.key.smart_mul_lsb_assign(block_left, block_right);
            });
    }
    pub fn smart_crt_mul_parallelized(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.smart_crt_mul_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }
}
