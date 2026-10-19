use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, ServerKey};

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 1u64;
    ///
    /// // Encrypt two messages:
    /// let ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// let ct_res = sks.neg_parallelized(&ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(255, dec);
    /// ```
    pub fn neg_parallelized<T>(&self, ctxt: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let ctxt = self.clean_for_default_op(ctxt);
        let mut result = self.bitnot(&*ctxt);
        self.scalar_add_assign_parallelized(&mut result, 1);
        result
    }

    pub fn overflowing_neg_parallelized<T>(&self, ctxt: &T) -> (T, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
    {
        // As we want to compute the overflow we need a truly clean state
        // And so we cannot avoid the cleaning like we may in non overflowing_block
        let ctxt = self.clean_for_default_op(ctxt);

        let mut result = self.bitnot(&*ctxt);
        let mut overflowed = self.overflowing_scalar_add_assign_parallelized(&mut result, 1);

        if !T::IS_SIGNED {
            // Computing overflow of !input + 1 only really works for signed integers
            // However for unsigned integers we can still get the correct result as the only
            // case where `!input + 1` overflows, is when `!input` == MAX (0b111..111) =>
            // `input == 0`.
            // And in unsigned integers, the only case that is not an overflow is -0,
            // so we can just invert the result
            self.boolean_bitnot_assign(&mut overflowed);
        }

        (result, overflowed)
    }
}
