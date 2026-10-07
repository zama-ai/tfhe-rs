use crate::integer::{BooleanBlock, ServerKey};

impl ServerKey {
    /// Computes homomorphically a bitand between two boolean ciphertexts
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_is_ge = sks.scalar_ge_parallelized(&ct, 10);
    /// let ct_is_le = sks.scalar_le_parallelized(&ct, 15);
    ///
    /// let ct_is_in_range = sks.boolean_bitand(&ct_is_ge, &ct_is_le);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_is_in_range);
    /// assert_eq!(dec_result, (10..=15).contains(&msg));
    /// ```
    pub fn boolean_bitand(&self, lhs: &BooleanBlock, rhs: &BooleanBlock) -> BooleanBlock {
        let result = self.key.bitand(&lhs.0, &rhs.0);
        BooleanBlock::new_unchecked(result)
    }

    pub fn boolean_bitand_assign(&self, lhs: &mut BooleanBlock, rhs: &BooleanBlock) {
        self.key.bitand_assign(&mut lhs.0, &rhs.0);
    }

    /// Computes homomorphically a bitor between two boolean ciphertexts
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_is_ge = sks.scalar_ge_parallelized(&ct, 10);
    /// let ct_is_le = sks.scalar_le_parallelized(&ct, 15);
    ///
    /// let ct_final_condition = sks.boolean_bitor(&ct_is_ge, &ct_is_le);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_final_condition);
    /// assert_eq!(dec_result, msg >= 10 || msg <= 15);
    /// ```
    pub fn boolean_bitor(&self, lhs: &BooleanBlock, rhs: &BooleanBlock) -> BooleanBlock {
        let result = self.key.bitor(&lhs.0, &rhs.0);
        BooleanBlock::new_unchecked(result)
    }

    pub fn boolean_bitor_assign(&self, lhs: &mut BooleanBlock, rhs: &BooleanBlock) {
        self.key.bitor_assign(&mut lhs.0, &rhs.0);
    }

    /// Computes homomorphically a bitxor between two boolean ciphertexts
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// let ct_is_ge = sks.scalar_ge_parallelized(&ct, 10);
    /// let ct_is_le = sks.scalar_le_parallelized(&ct, 15);
    ///
    /// let ct_final_condition = sks.boolean_bitxor(&ct_is_ge, &ct_is_le);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_final_condition);
    /// assert_eq!(dec_result, ((msg >= 10) ^ (msg <= 15)));
    /// ```
    pub fn boolean_bitxor(&self, lhs: &BooleanBlock, rhs: &BooleanBlock) -> BooleanBlock {
        let result = self.key.bitxor(&lhs.0, &rhs.0);
        BooleanBlock::new_unchecked(result)
    }

    pub fn boolean_bitxor_assign(&self, lhs: &mut BooleanBlock, rhs: &BooleanBlock) {
        self.key.bitxor_assign(&mut lhs.0, &rhs.0);
    }

    /// Computes homomorphically the bitnot of a boolean block
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg = true;
    ///
    /// let ct = cks.encrypt_bool(msg);
    ///
    /// let ct_res = sks.boolean_bitnot(&ct);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, !msg);
    /// ```
    pub fn boolean_bitnot(&self, boolean_block: &BooleanBlock) -> BooleanBlock {
        let mut result = boolean_block.clone();
        self.boolean_bitnot_assign(&mut result);
        result
    }
    pub fn boolean_bitnot_assign(&self, boolean_block: &mut BooleanBlock) {
        let original_modulus = boolean_block.0.message_modulus;
        // bitnot_assign uses the message modulus, which in the case of
        // a boolean block is implicitly 2, not the actual message mod
        // of the parameters
        boolean_block.0.message_modulus.0 = 2;
        self.key.bitnot_assign(&mut boolean_block.0);
        boolean_block.0.message_modulus = original_modulus;
    }
}

#[cfg(test)]
mod tests {
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::tests::create_parameterized_test;
    use crate::integer::{BooleanBlock, IntegerKeyKind};
    #[cfg(tarpaulin)]
    use crate::shortint::parameters::coverage_parameters::*;
    use crate::shortint::parameters::test_params::*;
    use crate::shortint::parameters::*;

    create_parameterized_test!(boolean_bitxor);
    create_parameterized_test!(boolean_bitor);
    create_parameterized_test!(boolean_bitand);

    const INPUT_BOOLEANS: [(bool, bool); 4] =
        [(false, false), (false, true), (true, false), (true, true)];

    fn boolean_bitxor(params: impl Into<TestParameters>) {
        let (cks, sks) = KEY_CACHE.get_from_params(params.into(), IntegerKeyKind::Radix);

        for (clear_0, clear_1) in INPUT_BOOLEANS {
            let mut ctxt_0 = cks.encrypt_one_block(u64::from(clear_0));
            let mut ctxt_1 = cks.encrypt_one_block(u64::from(clear_1));

            // We encrypted boolean values, but the encrypt function
            // does not leak that, so we force the degree
            ctxt_0.degree = Degree::new(1);
            ctxt_1.degree = Degree::new(1);

            let ctxt_0 = BooleanBlock::new_unchecked(ctxt_0);
            let ctxt_1 = BooleanBlock::new_unchecked(ctxt_1);

            let ct_res = sks.boolean_bitxor(&ctxt_0, &ctxt_1);
            assert_eq!(ct_res.0.degree.get(), 1);

            let dec_res = cks.decrypt_bool(&ct_res);
            assert_eq!(clear_0 ^ clear_1, dec_res);
        }
    }

    fn boolean_bitor(params: impl Into<TestParameters>) {
        let (cks, sks) = KEY_CACHE.get_from_params(params.into(), IntegerKeyKind::Radix);

        for (clear_0, clear_1) in INPUT_BOOLEANS {
            let mut ctxt_0 = cks.encrypt_one_block(u64::from(clear_0));
            let mut ctxt_1 = cks.encrypt_one_block(u64::from(clear_1));

            // We encrypted boolean values, but the encrypt function
            // does not leak that, so we force the degree
            ctxt_0.degree = Degree::new(1);
            ctxt_1.degree = Degree::new(1);

            let ctxt_0 = BooleanBlock::new_unchecked(ctxt_0);
            let ctxt_1 = BooleanBlock::new_unchecked(ctxt_1);

            let ct_res = sks.boolean_bitor(&ctxt_0, &ctxt_1);
            assert_eq!(ct_res.0.degree.get(), 1);

            let dec_res = cks.decrypt_bool(&ct_res);
            assert_eq!(clear_0 | clear_1, dec_res);
        }
    }

    fn boolean_bitand(params: impl Into<TestParameters>) {
        let (cks, sks) = KEY_CACHE.get_from_params(params.into(), IntegerKeyKind::Radix);

        for (clear_0, clear_1) in INPUT_BOOLEANS {
            let mut ctxt_0 = cks.encrypt_one_block(u64::from(clear_0));
            let mut ctxt_1 = cks.encrypt_one_block(u64::from(clear_1));

            // We encrypted boolean values, but the encrypt function
            // does not leak that, so we force the degree
            ctxt_0.degree = Degree::new(1);
            ctxt_1.degree = Degree::new(1);

            let ctxt_0 = BooleanBlock::new_unchecked(ctxt_0);
            let ctxt_1 = BooleanBlock::new_unchecked(ctxt_1);

            let ct_res = sks.boolean_bitand(&ctxt_0, &ctxt_1);
            assert_eq!(ct_res.0.degree.get(), 1);

            let dec_res = cks.decrypt_bool(&ct_res);
            assert_eq!(clear_0 & clear_1, dec_res);
        }
    }
}
