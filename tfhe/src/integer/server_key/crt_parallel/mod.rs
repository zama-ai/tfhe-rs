mod add_crt;
mod mul_crt;
mod neg_crt;
mod scalar_add_crt;
mod scalar_mul_crt;
mod scalar_sub_crt;
mod sub_crt;

use crate::integer::ciphertext::CrtCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    /// Extract all the messages.
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
    /// let ctxt_2 = cks.encrypt_crt(clear_2, basis);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_crt_add_assign(&mut ctxt_1, &ctxt_2);
    ///
    /// sks.full_extract_message_assign_parallelized(&mut ctxt_1);
    ///
    /// // Decrypt
    /// let res = cks.decrypt_crt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % 30, res);
    /// ```
    pub fn full_extract_message_assign_parallelized(&self, ctxt: &mut CrtCiphertext) {
        ctxt.blocks.par_iter_mut().for_each(|ct_i| {
            self.key.message_extract_assign(ct_i);
        });
    }

    /// Computes a PBS for CRT-compliant functions.
    ///
    /// # Warning
    ///
    /// This allows to compute programmable bootstrapping over integers under the condition that
    /// the function is said to be CRT-compliant. This means that the function should be correct
    /// when evaluated on each modular block independently (e.g. arithmetic functions).
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_2_CARRY_2_KS_PBS, basis);
    ///
    /// let clear_1 = 28;
    ///
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically the crt-compliant PBS
    /// sks.pbs_crt_compliant_function_assign_parallelized(&mut ctxt_1, |x| x * x * x);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_1 * clear_1) % 30, res);
    /// ```
    pub fn pbs_crt_compliant_function_assign_parallelized<F>(&self, ct1: &mut CrtCiphertext, f: F)
    where
        F: Fn(u64) -> u64,
    {
        let basis = &ct1.moduli;

        let lookup_tables = basis
            .iter()
            .copied()
            .map(|b| self.key.generate_lookup_table(|x| f(x) % b))
            .collect::<Vec<_>>();

        ct1.blocks
            .par_iter_mut()
            .zip(&lookup_tables)
            .for_each(|(block, acc)| {
                self.key.apply_lookup_table_assign(block, acc);
            });
    }

    pub fn pbs_crt_compliant_function_parallelized<F>(
        &self,
        ct1: &CrtCiphertext,
        f: F,
    ) -> CrtCiphertext
    where
        F: Fn(u64) -> u64,
    {
        let mut ct_res = ct1.clone();
        self.pbs_crt_compliant_function_assign_parallelized(&mut ct_res, f);
        ct_res
    }
}
