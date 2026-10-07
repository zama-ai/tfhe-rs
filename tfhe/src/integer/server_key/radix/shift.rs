use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

impl ServerKey {
    /// Shifts the blocks to the right.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 16;
    /// let shift = 2;
    ///
    /// // Encrypt two messages:
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.blockshift_right(&ct, shift);
    ///
    /// let div = cks.parameters().message_modulus().0.pow(shift as u32);
    ///
    /// // Decrypt:
    /// let clear: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg / div, clear);
    /// ```
    pub fn blockshift_right(&self, ctxt: &RadixCiphertext, shift: usize) -> RadixCiphertext {
        let mut result: RadixCiphertext = self.create_trivial_zero_radix(ctxt.blocks.len());

        let limit = result.blocks.len() - shift;

        for (res_i, c_i) in result.blocks[..limit]
            .iter_mut()
            .zip(ctxt.blocks[shift..].iter())
        {
            res_i.clone_from(c_i);
        }

        result
    }

    pub fn blockshift_right_assign(&self, ctxt: &mut RadixCiphertext, shift: usize) {
        *ctxt = self.blockshift_right(ctxt, shift);
    }
}
