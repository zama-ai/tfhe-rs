use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    /// Computes homomorphically a right shift.
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
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        shift: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a right shift.
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
    /// let msg = 18;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_right_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        shift: usize,
    ) {
        let tmp = self.key.message_modulus.0 as f64;

        //number of bits of message
        let nb_bits = tmp.log2() as usize;

        // 2^u = 2^{p*q+r} = 2^{p*(q+1)}*2^{r-p}
        let quotient = shift / nb_bits;

        //p-r
        let modified_remainder = nb_bits - (shift % nb_bits);

        //if r == 0
        if modified_remainder == nb_bits {
            self.full_propagate_parallelized(ct);
            self.blockshift_right_assign(ct, quotient);
        } else {
            // B/2^u = (B*2^{p-r}) / (2^{p*(q+1)})
            self.unchecked_scalar_left_shift_assign_parallelized(ct, modified_remainder);

            // We partially propagate in order to not lose information
            self.partial_propagate_parallelized(ct);
            self.blockshift_right_assign(ct, 1_usize);

            // We propagate the last block in order to not lose information
            self.propagate_parallelized(ct, ct.blocks.len() - 2);
            self.blockshift_right_assign(ct, quotient);
        }
    }

    /// Propagates all carries except the last one.
    /// For development purpose only.
    fn partial_propagate_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
    ) {
        let len = ctxt.blocks.len() - 1;
        for i in 0..len {
            self.propagate_parallelized(ctxt, i);
        }
    }

    /// Computes homomorphically a left shift by a scalar.
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
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &RadixCiphertext<PBSOrder>,
        shift: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct_left.clone();
        self.unchecked_scalar_left_shift_assign_parallelized(&mut result, shift);
        result
    }

    /// Computes homomorphically a left shift by a scalar.
    ///
    /// The result is assigned in the input ciphertext
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
    /// let msg = 13;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_left_shift_assign_parallelized(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_assign_parallelized<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        shift: usize,
    ) {
        let tmp = 1_u64 << shift;
        self.smart_scalar_mul_assign_parallelized(ct, tmp);
    }
}
