use crate::integer::ciphertext::CrtCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer
    /// values in the CRT decomposition.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_crt_add_assign_parallelized(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn unchecked_crt_add_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(&ct_right.blocks)
            .for_each(|(ct_left, ct_right)| {
                self.key.unchecked_add_assign(ct_left, ct_right);
            });
    }

    pub fn unchecked_crt_add_parallelized(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_crt_add_assign_parallelized(&mut ct_res, ct_right);
        ct_res
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values in
    /// the CRT decomposition.
    ///
    /// This checks that the addition is possible. In the case where the carry buffers are full,
    /// then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);
    ///
    /// let clear_1 = 29;
    /// let clear_2 = 29;
    ///
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.smart_crt_add_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn smart_crt_add_assign_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) {
        if !self.is_crt_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_extract_message_assign(ct_left),
                || self.full_extract_message_assign(ct_right),
            );
        }
        self.unchecked_crt_add_assign_parallelized(ct_left, ct_right);
    }

    pub fn smart_crt_add_parallelized(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        if !self.is_crt_add_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_extract_message_assign(ct_left),
                || self.full_extract_message_assign(ct_right),
            );
        }
        self.unchecked_crt_add_parallelized(ct_left, ct_right)
    }
}
