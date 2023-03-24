use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    pub fn unchecked_bitand_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign_parallelized(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitand_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(ct_right.blocks.par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_bitand_assign(ct_left_i, ct_right_i);
            });
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitand_parallelized(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 & msg2);
    /// ```
    pub fn smart_bitand_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitand_parallelized(ct_left, ct_right)
    }

    pub fn smart_bitand_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitand_assign_parallelized(ct_left, ct_right);
    }

    pub fn unchecked_bitor_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign_parallelized(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitor_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(ct_right.blocks.par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_bitor_assign(ct_left_i, ct_right_i);
            });
    }

    /// Computes homomorphically a bitor between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 | msg2);
    /// ```
    pub fn smart_bitor_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitor_parallelized(ct_left, ct_right)
    }

    pub fn smart_bitor_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitor_assign_parallelized(ct_left, ct_right);
    }

    pub fn unchecked_bitxor_parallelized(
        &self,
        ct_left: &RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign_parallelized(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitxor_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &RadixCiphertext,
    ) {
        ct_left
            .blocks
            .par_iter_mut()
            .zip(ct_right.blocks.par_iter())
            .for_each(|(ct_left_i, ct_right_i)| {
                self.key.unchecked_bitxor_assign(ct_left_i, ct_right_i);
            });
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, num_blocks);
    ///
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitxor_parallelized(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 ^ msg2);
    /// ```
    pub fn smart_bitxor_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitxor_parallelized(ct_left, ct_right)
    }

    pub fn smart_bitxor_assign_parallelized(
        &self,
        ct_left: &mut RadixCiphertext,
        ct_right: &mut RadixCiphertext,
    ) {
        if !self.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            rayon::join(
                || self.full_propagate_parallelized(ct_left),
                || self.full_propagate_parallelized(ct_right),
            );
        }
        self.unchecked_bitxor_assign_parallelized(ct_left, ct_right);
    }
}
