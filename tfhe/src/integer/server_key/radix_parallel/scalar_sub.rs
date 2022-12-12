use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

impl ServerKey {
    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_sub_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn smart_scalar_sub_parallelized(
        &self,
        ct: &mut RadixCiphertext,
        scalar: u64,
    ) -> RadixCiphertext {
        if !self.is_scalar_sub_possible(ct, scalar) {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_sub(ct, scalar)
    }

    pub fn smart_scalar_sub_assign_parallelized(&self, ct: &mut RadixCiphertext, scalar: u64) {
        if !self.is_scalar_sub_possible(ct, scalar) {
            self.full_propagate_parallelized(ct);
        }
        self.unchecked_scalar_sub_assign(ct, scalar);
    }
}
