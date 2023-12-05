use crate::integer::{CrtCiphertext, ServerKey};
use crate::shortint::CheckError;

impl ServerKey {
    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear = 14_u64;
    ///
    /// let mut ctxt = cks.encrypt(clear);
    ///
    /// sks.unchecked_crt_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!(16, res);
    /// ```
    pub fn unchecked_crt_neg(&self, ctxt: &CrtCiphertext) -> CrtCiphertext {
        let mut result = ctxt.clone();

        self.unchecked_crt_neg_assign(&mut result);

        result
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// This function computes the opposite of a message without checking if it exceeds the
    /// capacity of the ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    pub fn unchecked_crt_neg_assign(&self, ctxt: &mut CrtCiphertext) {
        for ct_i in ctxt.blocks.iter_mut() {
            self.key.unchecked_neg_assign(ct_i);
        }
    }

    /// Homomorphically computes the opposite of a ciphertext encrypting an integer message.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear = 14_u64;
    ///
    /// let mut ctxt = cks.encrypt(clear);
    ///
    /// sks.smart_crt_neg_assign(&mut ctxt);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt);
    /// assert_eq!(16, res);
    /// ```
    pub fn smart_crt_neg_assign(&self, ctxt: &mut CrtCiphertext) {
        if self.is_crt_neg_possible(ctxt).is_err() {
            self.full_extract_message_assign(ctxt);
        }
        self.is_crt_neg_possible(ctxt).unwrap();

        self.unchecked_crt_neg_assign(ctxt);
    }

    pub fn smart_crt_neg(&self, ctxt: &mut CrtCiphertext) -> CrtCiphertext {
        if self.is_crt_neg_possible(ctxt).is_err() {
            self.full_extract_message_assign(ctxt);
        }
        self.is_crt_neg_possible(ctxt).unwrap();
        self.unchecked_crt_neg(ctxt)
    }

    pub fn is_crt_neg_possible(&self, ctxt: &CrtCiphertext) -> Result<(), CheckError> {
        for ct_i in ctxt.blocks.iter() {
            self.key.is_neg_possible(ct_i.noise_degree())?;
        }
        Ok(())
    }
}
