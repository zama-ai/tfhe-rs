use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, size);
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
    pub fn smart_neg_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
    ) -> RadixCiphertext<PBSOrder> {
        if !self.is_neg_possible(ctxt) {
            self.full_propagate_parallelized(ctxt);
        }
        self.unchecked_neg(ctxt)
    }
}
