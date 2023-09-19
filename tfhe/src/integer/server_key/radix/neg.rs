use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::server_key::CheckError::CarryFull;
use crate::integer::ServerKey;

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Encrypt two messages:
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 159u64;
    ///
    /// // Encrypt a message
    /// let mut ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation
    /// sks.unchecked_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ctxt);
    /// assert_eq!(modulus - msg, dec);
    /// ```
    pub fn unchecked_neg<T>(&self, ctxt: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ctxt.clone();

        self.unchecked_neg_assign(&mut result);

        result
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    pub fn unchecked_neg_assign<T>(&self, ctxt: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        //z is used to make sure the negation doesn't fill the padding bit
        let mut z;
        let mut z_b;

        for i in 0..ctxt.blocks().len() {
            let c_i = &mut ctxt.blocks_mut()[i];
            z = self.key.unchecked_neg_assign_with_correcting_term(c_i);

            // Subtract z/B to the next ciphertext to compensate for the addition of z
            z_b = z / self.key.message_modulus.0 as u64;

            if i < ctxt.blocks().len() - 1 {
                let c_j = &mut ctxt.blocks_mut()[i + 1];
                self.key.unchecked_scalar_add_assign(c_j, z_b as u8);
            }
        }
    }

    /// Verifies if ct can be negated.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 2u64;
    ///
    /// // Encrypt a message
    /// let ctxt = cks.encrypt(msg);
    ///
    /// // Check if we can perform a negation
    /// let res = sks.is_neg_possible(&ctxt);
    ///
    /// assert_eq!(true, res);
    /// ```
    pub fn is_neg_possible<T>(&self, ctxt: &T) -> bool
    where
        T: IntegerRadixCiphertext,
    {
        for i in 0..ctxt.blocks().len() {
            // z = ceil( degree / 2^p ) x 2^p
            let msg_mod = self.key.message_modulus.0;
            let mut z = (ctxt.blocks()[i].degree.0 + msg_mod - 1) / msg_mod;
            z = z.wrapping_mul(msg_mod);

            // z will be the new degree of ctxt.blocks[i]
            if z > self.key.max_degree.0 {
                return false;
            }

            let z_b = z / msg_mod;

            if i < ctxt.blocks().len() - 1
                && !self
                    .key
                    .is_scalar_add_possible(&ctxt.blocks()[i + 1], z_b as u8)
            {
                return false;
            }
        }
        true
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
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
    /// // Encrypt a message
    /// let ctxt = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// let ct_res = sks.checked_neg(&ctxt);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(255, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_neg<T>(&self, ctxt: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        //If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt) {
            let mut result = ctxt.clone();
            self.unchecked_neg_assign(&mut result);
            Ok(result)
        } else {
            Err(CarryFull)
        }
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let modulus = 1 << 8;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 1;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically a negation:
    /// sks.checked_neg_assign(&mut ct);
    ///
    /// let clear_res: u64 = cks.decrypt(&ct);
    /// assert_eq!(clear_res, (modulus - msg));
    /// ```
    pub fn checked_neg_assign<T>(&self, ctxt: &mut T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        //If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt) {
            self.unchecked_neg_assign(ctxt);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

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
    /// let ct_res = sks.smart_neg(&mut ctxt);
    ///
    /// // Decrypt
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(255, dec);
    /// ```
    pub fn smart_neg<T>(&self, ctxt: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !self.is_neg_possible(ctxt) {
            self.full_propagate(ctxt);
        }
        self.unchecked_neg(ctxt)
    }
}
