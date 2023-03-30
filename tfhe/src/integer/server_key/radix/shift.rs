use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use crate::shortint::PBSOrderMarker;

impl ServerKey {
    /// Shifts the blocks to the right.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 16;
    /// let shift = 2;
    ///
    /// // Encrypt two messages:
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let ct_res = sks.blockshift_right(&mut ct, shift);
    ///
    /// let div = cks.parameters().message_modulus.0.pow(shift as u32) as u64;
    ///
    /// // Decrypt:
    /// let clear = cks.decrypt(&ct_res);
    /// assert_eq!(msg / div, clear);
    /// ```
    pub fn blockshift_right<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &RadixCiphertext<PBSOrder>,
        shift: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = self.create_trivial_zero_radix(ctxt.blocks.len());

        let limit = result.blocks.len() - shift;

        for (res_i, c_i) in result.blocks[..limit]
            .iter_mut()
            .zip(ctxt.blocks[shift..].iter())
        {
            *res_i = c_i.clone();
        }

        result
    }

    pub fn blockshift_right_assign<PBSOrder: PBSOrderMarker>(
        &self,
        ctxt: &mut RadixCiphertext<PBSOrder>,
        shift: usize,
    ) {
        *ctxt = self.blockshift_right(ctxt, shift);
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 128;
    /// let shift = 2;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_right_shift(&ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &RadixCiphertext<PBSOrder>,
        shift: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct.clone();
        self.unchecked_scalar_right_shift_assign(&mut result, shift);
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 18;
    /// let shift = 4;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_right_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg >> shift, dec);
    /// ```
    pub fn unchecked_scalar_right_shift_assign<PBSOrder: PBSOrderMarker>(
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
            self.full_propagate(ct);
            self.blockshift_right_assign(ct, quotient);
        } else {
            // B/2^u = (B*2^{p-r}) / (2^{p*(q+1)})
            self.unchecked_scalar_left_shift_assign(ct, modified_remainder);

            // We partially propagate in order to not lose information
            self.partial_propagate(ct);
            self.blockshift_right_assign(ct, 1_usize);

            // We propagate the last block in order to not lose information
            self.propagate(ct, ct.blocks.len() - 2);
            self.blockshift_right_assign(ct, quotient);
        }
    }

    /// Propagates all carries except the last one.
    /// For development purpose only.
    fn partial_propagate<PBSOrder: PBSOrderMarker>(&self, ctxt: &mut RadixCiphertext<PBSOrder>) {
        let len = ctxt.blocks.len() - 1;
        for i in 0..len {
            self.propagate(ctxt, i);
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 21;
    /// let shift = 2;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// let ct_res = sks.unchecked_scalar_left_shift(&ct1, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift<PBSOrder: PBSOrderMarker>(
        &self,
        ct_left: &RadixCiphertext<PBSOrder>,
        shift: usize,
    ) -> RadixCiphertext<PBSOrder> {
        let mut result = ct_left.clone();
        self.unchecked_scalar_left_shift_assign(&mut result, shift);
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg = 13;
    /// let shift = 2;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a right shift:
    /// sks.unchecked_scalar_left_shift_assign(&mut ct, shift);
    ///
    /// // Decrypt:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(msg << shift, dec);
    /// ```
    pub fn unchecked_scalar_left_shift_assign<PBSOrder: PBSOrderMarker>(
        &self,
        ct: &mut RadixCiphertext<PBSOrder>,
        shift: usize,
    ) {
        let tmp = 1_u64 << shift;
        self.smart_scalar_mul_assign(ct, tmp);
    }
}
