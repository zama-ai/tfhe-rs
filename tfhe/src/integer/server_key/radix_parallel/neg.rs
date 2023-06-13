use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.smart_neg_parallelized(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(255, dec);
    /// ```
    pub fn smart_neg_parallelized(&self, ctxt: &mut RadixCiphertext) -> RadixCiphertext {
        if !self.is_neg_possible(ctxt) {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_neg(ctxt)
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.neg_parallelized(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(255, dec);
    /// ```
    pub fn neg_parallelized(&self, ctxt: &RadixCiphertext) -> RadixCiphertext {
        let mut tmp_ctxt: RadixCiphertext;

        let ct = if !ctxt.block_carries_are_empty() {
            tmp_ctxt = ctxt.clone();
            self.full_propagate_parallelized(&mut tmp_ctxt);
            &tmp_ctxt
        } else {
            ctxt
        };

        if self.is_eligible_for_parallel_carryless_add() {
            let mut ct = self.unchecked_neg(ct);
            self.propagate_single_carry_parallelized_low_latency(&mut ct);
            ct
        } else {
            let mut ct = self.unchecked_neg(ct);
            self.full_propagate_parallelized(&mut ct);
            ct
        }
    }
}
