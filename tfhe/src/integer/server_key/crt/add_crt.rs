use crate::integer::{CrtCiphertext, ServerKey};
use crate::shortint::CheckError;

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_crt;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let basis = vec![2, 3, 5];
    /// let modulus: u64 = basis.iter().product();
    /// let (cks, sks) = gen_keys_crt(PARAM_MESSAGE_3_CARRY_3_KS_PBS, basis);
    ///
    /// let clear_1 = 14;
    /// let clear_2 = 14;
    /// // Encrypt two messages
    /// let mut ctxt_1 = cks.encrypt(clear_1);
    /// let mut ctxt_2 = cks.encrypt(clear_2);
    ///
    /// sks.smart_crt_add_assign(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt
    /// let res = cks.decrypt(&ctxt_1);
    /// assert_eq!((clear_1 + clear_2) % modulus, res);
    /// ```
    pub fn smart_crt_add(
        &self,
        ct_left: &mut CrtCiphertext,
        ct_right: &mut CrtCiphertext,
    ) -> CrtCiphertext {
        if self.is_crt_add_possible(ct_left, ct_right).is_err() {
            self.full_extract_message_assign(ct_left);
            self.full_extract_message_assign(ct_right);
        }
        self.is_crt_add_possible(ct_left, ct_right).unwrap();

        self.unchecked_crt_add(ct_left, ct_right)
    }

    pub fn smart_crt_add_assign(&self, ct_left: &mut CrtCiphertext, ct_right: &mut CrtCiphertext) {
        //If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_crt_add_possible(ct_left, ct_right).is_err() {
            self.full_extract_message_assign(ct_left);
            self.full_extract_message_assign(ct_right);
        }
        self.is_crt_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_crt_add_assign(ct_left, ct_right);
    }

    pub fn is_crt_add_possible(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> Result<(), CheckError> {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter().zip(ct_right.blocks.iter()) {
            self.key
                .is_add_possible(ct_left_i.noise_degree(), ct_right_i.noise_degree())?;
        }
        Ok(())
    }

    pub fn unchecked_crt_add_assign(&self, ct_left: &mut CrtCiphertext, ct_right: &CrtCiphertext) {
        for (ct_left_i, ct_right_i) in ct_left.blocks.iter_mut().zip(ct_right.blocks.iter()) {
            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
        }
    }

    pub fn unchecked_crt_add(
        &self,
        ct_left: &CrtCiphertext,
        ct_right: &CrtCiphertext,
    ) -> CrtCiphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_crt_add_assign(&mut ct_res, ct_right);
        ct_res
    }
}
