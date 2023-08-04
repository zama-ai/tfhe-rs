use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;
use rayon::prelude::*;

impl ServerKey {
    pub fn unchecked_if_then_else_parallelized(
        &self,
        condition: &RadixCiphertext,
        true_ct: &RadixCiphertext,
        false_ct: &RadixCiphertext,
    ) -> RadixCiphertext {
        assert!(
            condition.holds_boolean_value(),
            "The condition ciphertext does not encrypt a boolean (0 or 1) value"
        );

        let condition_block = &condition.blocks[0];
        self.unchecked_programmable_if_then_else_parallelized(
            condition_block,
            true_ct,
            false_ct,
            |x| x == 1,
        )
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
    /// ```
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
    pub fn if_then_else_parallelized(
        &self,
        condition: &RadixCiphertext,
        true_ct: &RadixCiphertext,
        false_ct: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_clones = [None, None, None];
        let mut ct_refs = [condition, true_ct, false_ct];

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

        let [condition, true_ct, false_ct] = ct_refs;
        self.unchecked_if_then_else_parallelized(condition, true_ct, false_ct)
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
    /// ```
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
    pub fn smart_if_then_else_parallelized(
        &self,
        condition: &mut RadixCiphertext,
        true_ct: &mut RadixCiphertext,
        false_ct: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_refs = [condition, true_ct, false_ct];

        ct_refs.par_iter_mut().for_each(|ct_ref| {
            if !ct_ref.block_carries_are_empty() {
                self.full_propagate_parallelized(*ct_ref);
            }
        });

        let [condition, true_ct, false_ct] = ct_refs;
        self.unchecked_if_then_else_parallelized(condition, true_ct, false_ct)
    }

    pub(crate) fn unchecked_programmable_if_then_else_parallelized<F>(
        &self,
        condition_block: &crate::shortint::Ciphertext,
        true_ct: &RadixCiphertext,
        false_ct: &RadixCiphertext,
        predicate: F,
    ) -> RadixCiphertext
    where
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
        true_ct
            .blocks
            .par_iter_mut()
            .zip(false_ct.blocks.par_iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key.unchecked_add_assign(lhs_block, rhs_block);
                self.key.message_extract_assign(lhs_block)
            });
        true_ct
    }

    /// This function takes a ciphertext encrypting any integer value
    /// and block encrypting a boolean value (0 or 1).
    ///
    /// The input integer ciphertext will have all its block zeroed if condition_block
    /// encrypts 0, otherwise each block keeps its value.
    pub(crate) fn zero_out_if_condition_is_false(
        &self,
        ct: &mut RadixCiphertext,
        condition_block: &crate::shortint::Ciphertext,
    ) {
        assert!(condition_block.degree.0 <= 1);

        self.zero_out_if_condition_equals(ct, condition_block, 0)
    }

    pub(crate) fn zero_out_if_condition_equals(
        &self,
        ct: &mut RadixCiphertext,
        condition_block: &crate::shortint::Ciphertext,
        value: u64,
    ) {
        assert!(condition_block.degree.0 < condition_block.message_modulus.0);
        assert!(value < condition_block.message_modulus.0 as u64);

        self.zero_out_if(ct, condition_block, |x| x == value);
    }

    pub(crate) fn zero_out_if<F>(
        &self,
        ct: &mut RadixCiphertext,
        condition_block: &crate::shortint::Ciphertext,
        predicate: F,
    ) where
        F: Fn(u64) -> bool,
    {
        assert!(condition_block.degree.0 < condition_block.message_modulus.0);

        if condition_block.degree.0 == 0 {
            return self.create_trivial_zero_assign_radix(ct);
        }

        let lut =
            self.key.generate_lookup_table_bivariate(
                |block, condition| if predicate(condition) { 0 } else { block },
            );

        ct.blocks
            .par_iter_mut()
            .filter(|block| block.degree.0 != 0)
            .for_each(|block| {
                self.key.unchecked_apply_lookup_table_bivariate_assign(
                    block,
                    condition_block,
                    &lut,
                );
            });
    }
}
