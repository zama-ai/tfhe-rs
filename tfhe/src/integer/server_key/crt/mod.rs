use crate::integer::ciphertext::CrtCiphertext;
use crate::integer::ServerKey;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn make_basis(message_modulus: u64) -> Vec<u64> {
    match message_modulus {
        2 => vec![2],
        3 => vec![2],
        n if n < 8 => vec![2, 3],
        n if n < 16 => vec![2, 5, 7],
        _ => vec![3, 7, 13],
    }
}

mod add_crt;
mod mul_crt;
mod neg_crt;
mod scalar_add_crt;
mod scalar_mul_crt;
mod scalar_sub_crt;
mod sub_crt;

impl ServerKey {
    /// Extract all the messages.
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
    /// let ctxt_2 = cks.encrypt(clear_2);
    ///
    /// // Compute homomorphically a multiplication
    /// sks.unchecked_crt_add_assign(&mut ctxt_1, &ctxt_2);
    ///
    /// sks.full_extract_message_assign(&mut ctxt_1);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % modulus, res);
    /// ```
    pub fn full_extract_message_assign(&self, ctxt: &mut CrtCiphertext) {
        for ct_i in ctxt.blocks.iter_mut() {
            self.key.message_extract_assign(ct_i);
        }
    }

    /// Computes a PBS for CRT-compliant functions.
    ///
    /// # Warning
    /// This allows to compute programmable bootstrapping over integers under the condition that
    /// the function is said to be CRT-compliant. This means that the function should be correct
    /// when evaluated on each modular block independently (e.g. arithmetic functions).
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
    /// let clear_1 = 28;
    ///
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    ///
    /// // Compute homomorphically the crt-compliant PBS
    /// sks.pbs_crt_compliant_function_assign(&mut ctxt_1, |x| x * x * x);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 * clear_1 * clear_1) % modulus, res);
    /// ```
    pub fn pbs_crt_compliant_function_assign<F>(&self, ct1: &mut CrtCiphertext, f: F)
    where
        F: Fn(u64) -> u64,
    {
        let basis = &ct1.moduli;

        let lookup_tables = basis
            .iter()
            .copied()
            .map(|b| self.key.generate_lookup_table(|x| f(x) % b));

        for (block, acc) in ct1.blocks.iter_mut().zip(lookup_tables) {
            self.key.apply_lookup_table_assign(block, &acc);
        }
    }

    pub fn pbs_crt_compliant_function<F>(&self, ct1: &CrtCiphertext, f: F) -> CrtCiphertext
    where
        F: Fn(u64) -> u64,
    {
        let mut ct_res = ct1.clone();
        self.pbs_crt_compliant_function_assign(&mut ct_res, f);
        ct_res
    }
}
