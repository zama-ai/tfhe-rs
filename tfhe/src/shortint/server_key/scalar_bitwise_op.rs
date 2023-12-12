use super::ServerKey;
use crate::shortint::Ciphertext;

impl ServerKey {
    /// Compute homomorphically a bitwise AND between a ciphertext and a clear value
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 3u64;
    /// let msg2 = 2u64;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Compute homomorphically an AND:
    /// let ct_res = sks.scalar_bitand(&ct1, msg2 as u8);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 & msg2, res);
    /// ```
    pub fn scalar_bitand(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut ct_res = lhs.clone();
        self.scalar_bitand_assign(&mut ct_res, rhs);
        ct_res
    }

    pub fn scalar_bitand_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        if !lhs.carry_is_empty() {
            self.message_extract_assign(lhs);
        }

        self.unchecked_scalar_bitand_assign(lhs, rhs);
    }

    pub fn unchecked_scalar_bitand(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitand_assign(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitand_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.evaluate_msg_univariate_function_assign(lhs, |x| x & rhs as u64);
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_bitand(&self, lhs: &mut Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.smart_scalar_bitand_assign(&mut result, rhs);
        result
    }

    pub fn smart_scalar_bitand_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.unchecked_scalar_bitand_assign(lhs, rhs);
    }

    /// Compute homomorphically a bitwise XOR between a ciphertext and a clear value
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 3u64;
    /// let msg2 = 2u64;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Compute homomorphically a XOR:
    /// let ct_res = sks.scalar_bitxor(&ct1, msg2 as u8);
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 ^ msg2, res);
    /// ```
    pub fn scalar_bitxor(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut ct_res = lhs.clone();
        self.scalar_bitxor_assign(&mut ct_res, rhs);
        ct_res
    }

    pub fn scalar_bitxor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        if !lhs.carry_is_empty() {
            self.message_extract_assign(lhs);
        }

        self.unchecked_scalar_bitxor_assign(lhs, rhs);
    }

    pub fn unchecked_scalar_bitxor(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitxor_assign(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitxor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.evaluate_msg_univariate_function_assign(lhs, |x| x ^ rhs as u64);
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_bitxor(&self, lhs: &mut Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.smart_scalar_bitxor_assign(&mut result, rhs);
        result
    }
    pub fn smart_scalar_bitxor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.unchecked_scalar_bitxor_assign(lhs, rhs);
    }

    /// Compute homomorphically a bitwise OR between a ciphertext and a clear value
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg1 = 3u64;
    /// let msg2 = 2u64;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Compute homomorphically an OR:
    /// let ct_res = sks.scalar_bitor(&ct1, msg2 as u8);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 | msg2, res);
    /// ```
    pub fn scalar_bitor(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut ct_res = lhs.clone();
        self.scalar_bitor_assign(&mut ct_res, rhs);
        ct_res
    }

    pub fn scalar_bitor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        if !lhs.carry_is_empty() {
            self.message_extract_assign(lhs);
        }

        self.unchecked_scalar_bitor_assign(lhs, rhs);
    }

    pub fn unchecked_scalar_bitor(&self, lhs: &Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.unchecked_scalar_bitor_assign(&mut result, rhs);
        result
    }

    pub fn unchecked_scalar_bitor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.evaluate_msg_univariate_function_assign(lhs, |x| x | rhs as u64);
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn smart_scalar_bitor(&self, lhs: &mut Ciphertext, rhs: u8) -> Ciphertext {
        let mut result = lhs.clone();
        self.smart_scalar_bitor_assign(&mut result, rhs);
        result
    }

    pub fn smart_scalar_bitor_assign(&self, lhs: &mut Ciphertext, rhs: u8) {
        self.unchecked_scalar_bitor_assign(lhs, rhs);
    }
}
