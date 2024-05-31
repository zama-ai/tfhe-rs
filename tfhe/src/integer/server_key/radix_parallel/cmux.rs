use crate::integer::ciphertext::boolean_value::BooleanBlock;
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

pub trait ServerKeyDefaultCMux<TrueCt, FalseCt> {
    type Output;
    fn if_then_else_parallelized(
        &self,
        condition: &BooleanBlock,
        true_ct: TrueCt,
        false_ct: FalseCt,
    ) -> Self::Output;

    fn select_parallelized(
        &self,
        condition: &BooleanBlock,
        ct_when_true: TrueCt,
        ct_when_false: FalseCt,
    ) -> Self::Output {
        self.if_then_else_parallelized(condition, ct_when_true, ct_when_false)
    }

    fn cmux_parallelized(
        &self,
        condition: &BooleanBlock,
        true_ct: TrueCt,
        false_ct: FalseCt,
    ) -> Self::Output {
        self.if_then_else_parallelized(condition, true_ct, false_ct)
    }
}

impl<T> ServerKeyDefaultCMux<&T, &T> for ServerKey
where
    T: IntegerRadixCiphertext,
{
    type Output = T;

    /// FHE "if then else" selection.
    ///
    /// Returns a new ciphertext that encrypts the same value
    /// as either true_ct or false_ct depending on the value of condition:
    ///
    /// - If condition == 1, the returned ciphertext will encrypt the same value as true_ct.
    /// - If condition == 0, the returned ciphertext will encrypt the same value as false_ct.
    ///
    /// To ensure correct results, condition must encrypt either 0 or 1
    /// (e.g result from a comparison).
    ///
    /// Note that while the returned ciphertext encrypts the same value as
    /// either true_ct or false_ct, it won't exactly be true_ct or false_ct.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::prelude::*;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let a = 128u8;
    /// let b = 55u8;
    ///
    /// let ct_a = cks.encrypt(a);
    /// let ct_b = cks.encrypt(b);
    ///
    /// let condition = sks.scalar_ge_parallelized(&ct_a, 66);
    ///
    /// let ct_res = sks.if_then_else_parallelized(&condition, &ct_a, &ct_b);
    ///
    /// // Decrypt:
    /// let dec: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(if a >= 66 { a } else { b }, dec);
    /// assert_ne!(ct_a, ct_res);
    /// assert_ne!(ct_b, ct_res);
    /// ```
    fn if_then_else_parallelized(
        &self,
        condition: &BooleanBlock,
        true_ct: &T,
        false_ct: &T,
    ) -> Self::Output {
        let mut ct_clones = [None, None];
        let mut ct_refs = [true_ct, false_ct];

        ct_refs
            .par_iter_mut()
            .zip(ct_clones.par_iter_mut())
            .for_each(|(ct_ref, ct_clone)| {
                if !ct_ref.block_carries_are_empty() {
                    let mut cloned = ct_ref.clone();
                    self.full_propagate_parallelized(&mut cloned);
                    *ct_ref = ct_clone.insert(cloned);
                }
            });

        let [true_ct, false_ct] = ct_refs;
        self.unchecked_if_then_else_parallelized(condition, true_ct, false_ct)
    }
}

impl ServerKeyDefaultCMux<&BooleanBlock, &BooleanBlock> for ServerKey {
    type Output = BooleanBlock;

    /// FHE "if then else" selection.
    ///
    /// Returns a new ciphertext that encrypts the same value
    /// as either true_ct or false_ct depending on the value of condition:
    ///
    /// - If condition == 1, the returned ciphertext will encrypt the same value as true_ct.
    /// - If condition == 0, the returned ciphertext will encrypt the same value as false_ct.
    ///
    /// To ensure correct results, condition must encrypt either 0 or 1
    /// (e.g result from a comparison).
    ///
    /// Note that while the returned ciphertext encrypts the same value as
    /// either true_ct or false_ct, it won't exactly be true_ct or false_ct.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::integer::prelude::*;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// for cond in [true, false] {
    ///     for a in [true, false] {
    ///         for b in [true, false] {
    ///             let condition = cks.encrypt_bool(cond);
    ///             let ct_a = cks.encrypt_bool(a);
    ///             let ct_b = cks.encrypt_bool(b);
    ///
    ///             let ct_res = sks.if_then_else_parallelized(&condition, &ct_a, &ct_b);
    ///
    ///             // Decrypt:
    ///             let dec = cks.decrypt_bool(&ct_res);
    ///             assert_eq!(if cond { a } else { b }, dec);
    ///             assert_ne!(ct_a, ct_res);
    ///             assert_ne!(ct_b, ct_res);
    ///         }
    ///     }
    /// }
    /// ```
    fn if_then_else_parallelized(
        &self,
        condition: &BooleanBlock,
        true_ct: &BooleanBlock,
        false_ct: &BooleanBlock,
    ) -> Self::Output {
        let total_nb_bits = (self.message_modulus().0 * self.carry_modulus().0).ilog2();
        assert!(
            total_nb_bits >= 2,
            "At least 2 bits of plaintext are required"
        );

        let zero_lut = self.key.generate_lookup_table(|x| {
            let cond = (x >> 1) & 1 == 1;
            let value = x & 1;

            if cond {
                value
            } else {
                0
            }
        });

        let negated_cond = self.boolean_bitnot(condition);

        let (mut lhs, rhs) = rayon::join(
            || {
                let mut block = self.key.scalar_mul(&condition.0, 2);
                self.key.unchecked_add_assign(&mut block, &true_ct.0);
                self.key.apply_lookup_table_assign(&mut block, &zero_lut);
                block
            },
            || {
                let mut block = self.key.scalar_mul(&negated_cond.0, 2);
                self.key.unchecked_add_assign(&mut block, &false_ct.0);
                self.key.apply_lookup_table_assign(&mut block, &zero_lut);
                block
            },
        );

        self.key.unchecked_add_assign(&mut lhs, &rhs);
        let clean_lut = self.key.generate_lookup_table(|x| x % 2);
        self.key.apply_lookup_table_assign(&mut lhs, &clean_lut);

        BooleanBlock::new_unchecked(lhs)
    }
}

impl ServerKey {
    pub fn unchecked_if_then_else_parallelized<T>(
        &self,
        condition: &BooleanBlock,
        true_ct: &T,
        false_ct: &T,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let condition_block = &condition.0;
        let do_clean_message = true;
        self.unchecked_programmable_if_then_else_parallelized(
            condition_block,
            true_ct,
            false_ct,
            |x| x == 1,
            do_clean_message,
        )
    }

    pub fn unchecked_cmux<T>(&self, condition: &BooleanBlock, true_ct: &T, false_ct: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.unchecked_if_then_else_parallelized(condition, true_ct, false_ct)
    }

    /// Encrypted CMUX.
    ///
    /// It is another name for [Self::if_then_else_parallelized]
    pub fn cmux_parallelized<T>(&self, condition: &BooleanBlock, true_ct: &T, false_ct: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.if_then_else_parallelized(condition, true_ct, false_ct)
    }

    /// FHE "if then else" selection.
    ///
    /// Returns a new ciphertext that encrypts the same value
    /// as either true_ct or false_ct depending on the value of condition:
    ///
    /// - If condition == 1, the returned ciphertext will encrypt the same value as true_ct.
    /// - If condition == 0, the returned ciphertext will encrypt the same value as false_ct.
    ///
    /// To ensure correct results, condition must encrypt either 0 or 1
    /// (e.g result from a comparison).
    ///
    /// Note that while the returned ciphertext encrypts the same value as
    /// either true_ct or false_ct, it won't exactly be true_ct or false_ct.
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let a = 128u8;
    /// let b = 55u8;
    ///
    /// let mut ct_a = cks.encrypt(a);
    /// let mut ct_b = cks.encrypt(b);
    ///
    /// let mut condition = sks.scalar_ge_parallelized(&ct_a, 66);
    ///
    /// let ct_res = sks.smart_if_then_else_parallelized(&mut condition, &mut ct_a, &mut ct_b);
    ///
    /// // Decrypt:
    /// let dec: u8 = cks.decrypt(&ct_res);
    /// assert_eq!(if a >= 66 { a } else { b }, dec);
    /// assert_ne!(ct_a, ct_res);
    /// assert_ne!(ct_b, ct_res);
    /// ```
    pub fn smart_if_then_else_parallelized<T>(
        &self,
        condition: &mut BooleanBlock,
        true_ct: &mut T,
        false_ct: &mut T,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if !condition.0.carry_is_empty() {
            self.key.message_extract_assign(&mut condition.0);
        }
        let mut ct_refs = [true_ct, false_ct];

        ct_refs.par_iter_mut().for_each(|ct_ref| {
            if !ct_ref.block_carries_are_empty() {
                self.full_propagate_parallelized(*ct_ref);
            }
        });

        let [true_ct, false_ct] = ct_refs;
        self.unchecked_if_then_else_parallelized(condition, true_ct, false_ct)
    }

    /// Encrypted CMUX.
    ///
    /// It is another name for [Self::smart_if_then_else_parallelized]
    pub fn smart_cmux_parallelized<T>(
        &self,
        condition: &mut BooleanBlock,
        true_ct: &mut T,
        false_ct: &mut T,
    ) -> T
    where
        T: IntegerRadixCiphertext,
    {
        self.smart_if_then_else_parallelized(condition, true_ct, false_ct)
    }

    /// if do clean message is false, the resulting ciphertext won't be cleaned (message_extract)
    /// meaning that yes, the resulting ciphertext's encrypted message is within 0..msg_msg
    /// but its degree is the same as after adding to ciphertext
    ///
    /// TLDR: do_clean_message should be false only if you plan on doing your own PBS
    /// soon after. (may need to force degree yourself not to trigger asserts)
    // Note: do_clean_message is needed until degree is used for both
    // message range and noise management.
    pub(crate) fn unchecked_programmable_if_then_else_parallelized<T, F>(
        &self,
        condition_block: &crate::shortint::Ciphertext,
        true_ct: &T,
        false_ct: &T,
        predicate: F,
        do_clean_message: bool,
    ) -> T
    where
        T: IntegerRadixCiphertext,
        F: Fn(u64) -> bool + Send + Sync + Copy,
    {
        let inverted_predicate = |x| !predicate(x);

        // Although our mul algorithm has special path for when rhs or lhs is a boolean value,
        // we don't call it as for the ct_false we would need an extra pbs to 'invert' the
        // ciphertext from true to false.
        let (mut true_ct, false_ct) = rayon::join(
            move || {
                let mut true_ct = true_ct.clone();
                self.zero_out_if(&mut true_ct, condition_block, inverted_predicate);
                true_ct
            },
            move || {
                let mut false_ct = false_ct.clone();
                self.zero_out_if(&mut false_ct, condition_block, predicate);
                false_ct
            },
        );
        // If the condition was true, true_ct will have kept its value and false_ct will be 0
        // If the condition was false, true_ct will be 0 and false_ct will have kept its value
        //
        // If we don't need to clean ciphertext, then we have no PBS to do, so no
        // need to use multi-threading
        if do_clean_message {
            true_ct
                .blocks_mut()
                .par_iter_mut()
                .zip(false_ct.blocks().par_iter())
                .for_each(|(lhs_block, rhs_block)| {
                    self.key.unchecked_add_assign(lhs_block, rhs_block);
                    self.key.message_extract_assign(lhs_block);
                });
        } else {
            true_ct
                .blocks_mut()
                .iter_mut()
                .zip(false_ct.blocks().iter())
                .for_each(|(lhs_block, rhs_block)| {
                    self.key.unchecked_add_assign(lhs_block, rhs_block);
                });
        }

        true_ct
    }

    /// This function takes a ciphertext encrypting any integer value
    /// and block encrypting a boolean value (0 or 1).
    ///
    /// The input integer ciphertext will have all its block zeroed if condition_block
    /// encrypts 0, otherwise each block keeps its value.
    pub(crate) fn zero_out_if_condition_is_false<T>(
        &self,
        ct: &mut T,
        condition_block: &crate::shortint::Ciphertext,
    ) where
        T: IntegerRadixCiphertext,
    {
        assert!(condition_block.degree.get() <= 1);

        self.zero_out_if_condition_equals(ct, condition_block, 0);
    }

    pub(crate) fn zero_out_if_condition_equals<T>(
        &self,
        ct: &mut T,
        condition_block: &crate::shortint::Ciphertext,
        value: u64,
    ) where
        T: IntegerRadixCiphertext,
    {
        assert!(condition_block.degree.get() < condition_block.message_modulus.0);
        assert!(value < condition_block.message_modulus.0 as u64);

        self.zero_out_if(ct, condition_block, |x| x == value);
    }

    pub(crate) fn zero_out_if<T, F>(
        &self,
        ct: &mut T,
        condition_block: &crate::shortint::Ciphertext,
        predicate: F,
    ) where
        T: IntegerRadixCiphertext,
        F: Fn(u64) -> bool,
    {
        assert!(condition_block.degree.get() < condition_block.message_modulus.0);

        if condition_block.degree.get() == 0 {
            // The block 'encrypts'  0, and only 0
            if predicate(0u64) {
                self.create_trivial_zero_assign_radix(ct);
            }
            // else, condition is false, don't do anything
            return;
        }

        let lut =
            self.key.generate_lookup_table_bivariate(
                |block, condition| if predicate(condition) { 0 } else { block },
            );

        ct.blocks_mut()
            .par_iter_mut()
            .filter(|block| block.degree.get() != 0)
            .for_each(|block| {
                self.key.unchecked_apply_lookup_table_bivariate_assign(
                    block,
                    condition_block,
                    &lut,
                );
            });
    }
}
