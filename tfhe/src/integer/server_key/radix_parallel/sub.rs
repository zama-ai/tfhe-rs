use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::ciphertext::Degree;
use crate::shortint::Ciphertext;
use rayon::prelude::*;
use std::cmp::Ordering;

#[repr(u64)]
#[derive(PartialEq, Eq)]
enum BorrowGeneration {
    /// The block does not generate nor propagate a borrow
    None = 0,
    /// The block generates a borrow (that will be taken from next block)
    Generated = 1,
    /// The block will propagate a borrow if ever
    /// the preceding blocks borrows from it
    Propagated = 2,
}

impl ServerKey {
    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.smart_sub_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);

        result
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let mut ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.smart_sub_assign_parallelized(&mut ctxt_1, &mut ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn smart_sub_assign_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if self.is_neg_possible(ctxt_right).is_err() {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_sub_possible(ctxt_left, ctxt_right).is_err() {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }
        self.is_sub_possible(ctxt_left, ctxt_right).unwrap();

        self.unchecked_sub_assign(ctxt_left, ctxt_right);
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// let ct_res = sks.sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub_parallelized<T>(&self, ctxt_left: &T, ctxt_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ctxt_left.clone();
        self.sub_assign_parallelized(&mut ct_res, ctxt_right);
        ct_res
    }

    /// Computes homomorphically the subtraction between ct_left and ct_right.
    ///
    /// This function, like all "default" operations (i.e. not smart, checked or unchecked), will
    /// check that the input ciphertexts block carries are empty and clears them if it's not the
    /// case and the operation requires it. It outputs a ciphertext whose block carries are always
    /// empty.
    ///
    /// This means that when using only "default" operations, a given operation (like add for
    /// example) has always the same performance characteristics from one call to another and
    /// guarantees correctness by pre-emptively clearing carries of output ciphertexts.
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
    /// let msg_1 = 120u8;
    /// let msg_2 = 181u8;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1 as u64);
    /// let ctxt_2 = cks.encrypt(msg_2 as u64);
    ///
    /// // Compute homomorphically a subtraction
    /// sks.sub_assign_parallelized(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let res: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(msg_1.wrapping_sub(msg_2) as u64, res);
    /// ```
    pub fn sub_assign_parallelized<T>(&self, ctxt_left: &mut T, ctxt_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                self.full_propagate_parallelized(ctxt_left);
                (ctxt_left, ctxt_right)
            }
            (false, false) => {
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(ctxt_left),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (ctxt_left, &tmp_rhs)
            }
        };

        let neg = self.unchecked_neg(rhs);
        self.add_assign_with_carry(lhs, &neg, None);
    }

    /// Computes the subtraction and returns an indicator of overflow
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg_1 = 1u8;
    /// let msg_2 = 255u8;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction
    /// let (result, overflowed) = sks.unsigned_overflowing_sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let decrypted_result: u8 = cks.decrypt(&result);
    /// let decrypted_overflow = cks.decrypt_bool(&overflowed);
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn unsigned_overflowing_sub_parallelized(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ctxt_left.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, ctxt_right)
            }
            (false, false) => {
                tmp_lhs = ctxt_left.clone();
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_unsigned_overflowing_sub(lhs, rhs)
    }

    pub fn unchecked_unsigned_overflowing_sub_parallelized(
        &self,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
    ) -> (RadixCiphertext, BooleanBlock) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );
        // Here we have to use manual unchecked_sub on shortint blocks
        // rather than calling integer's unchecked_sub as we need each subtraction
        // to be independent of other blocks. And we don't want to do subtraction by
        // adding negation
        let ct = lhs
            .blocks
            .iter()
            .zip(rhs.blocks.iter())
            .map(|(lhs_block, rhs_block)| self.key.unchecked_sub(lhs_block, rhs_block))
            .collect::<Vec<_>>();
        let mut ct = RadixCiphertext::from(ct);
        let overflowed = self.unsigned_overflowing_propagate_subtraction_borrow(&mut ct);
        (ct, overflowed)
    }

    /// This function takes a ciphertext resulting from a subtraction of 2 clean ciphertexts
    /// **USING SHORTINT'S UNCHECKED_SUB SEPARATELY ON EACH BLOCK**, that is after subtracting
    /// blocks, the values are in range 0..(2*msg_modulus) e.g 0..7 for 2_2 parameters
    /// where:
    ///   - if ct's value is in 0..msg_mod -> the block overflowed (needs to borrow from next block)
    ///   - if ct's value is in msg_mod..2*msg_mod the block did not overflow (ne need to borrow
    ///
    ///
    /// It propagates the borrows in-place, making the ciphertext clean and returns
    /// the boolean indicating overflow
    pub(in crate::integer) fn unsigned_overflowing_propagate_subtraction_borrow(
        &self,
        ct: &mut RadixCiphertext,
    ) -> BooleanBlock {
        if self.is_eligible_for_parallel_single_carry_propagation(ct) {
            let generates_or_propagates = self.generate_init_borrow_array(ct);
            let (input_borrows, mut output_borrow) =
                self.compute_borrow_propagation_parallelized_low_latency(generates_or_propagates);

            ct.blocks
                .par_iter_mut()
                .zip(input_borrows.par_iter())
                .for_each(|(block, input_borrow)| {
                    // Do a true lwe subtraction, as unchecked_sub will adds a correcting term
                    // to avoid overflow (and trashing padding bit). Here we know each
                    // block in the ciphertext is >= 1, and that input borrow is either 0 or 1
                    // so no overflow possible.
                    crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                        &mut block.ct,
                        &input_borrow.ct,
                    );
                    block.set_noise_level(block.noise_level() + input_borrow.noise_level());
                    self.key.message_extract_assign(block);
                });
            assert!(ct.block_carries_are_empty());
            // we know here that the result is a boolean value
            // however the lut used has a degree of 2.
            output_borrow.degree = Degree::new(1);
            BooleanBlock::new_unchecked(output_borrow)
        } else {
            let modulus = self.key.message_modulus.0 as u64;

            // If the block does not have a carry after the subtraction, it means it needs to
            // borrow from the next block
            let compute_borrow_lut =
                self.key
                    .generate_lookup_table(|x| if x < modulus { 1 } else { 0 });

            let mut borrow = self.key.create_trivial(0);
            for block in ct.blocks.iter_mut() {
                // Here unchecked_sub_assign does not give correct result, we don't want
                // the correcting term to be used
                // -> This is ok as the value returned by unchecked_sub is in range 1..(message_mod
                // * 2)
                crate::core_crypto::algorithms::lwe_ciphertext_sub_assign(
                    &mut block.ct,
                    &borrow.ct,
                );
                block.set_noise_level(block.noise_level() + borrow.noise_level());
                let (msg, new_borrow) = rayon::join(
                    || self.key.message_extract(block),
                    || self.key.apply_lookup_table(block, &compute_borrow_lut),
                );
                *block = msg;
                borrow = new_borrow;
            }

            // borrow of last block indicates overflow
            BooleanBlock::new_unchecked(borrow)
        }
    }

    pub fn unchecked_signed_overflowing_sub_parallelized(
        &self,
        lhs: &SignedRadixCiphertext,
        rhs: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        assert_eq!(
            lhs.blocks.len(),
            rhs.blocks.len(),
            "Left hand side must must have a number of blocks equal \
            to the number of blocks of the right hand side: lhs {} blocks, rhs {} blocks",
            lhs.blocks.len(),
            rhs.blocks.len()
        );

        let flipped_rhs = self.bitnot(rhs);
        let input_carry = self.create_trivial_boolean_block(true);
        let mut result = lhs.clone();
        let overflowed =
            self.overflowing_add_assign_with_carry(&mut result, &flipped_rhs, Some(&input_carry));
        (result, overflowed)
    }

    pub(super) fn generate_init_borrow_array(&self, sum_ct: &RadixCiphertext) -> Vec<Ciphertext> {
        let modulus = self.key.message_modulus.0 as u64;

        // This is used for the first pair of blocks
        // as this pair can either generate or not, but never propagate
        let lut_does_block_generate_carry = self.key.generate_lookup_table(|x| {
            if x < modulus {
                BorrowGeneration::Generated as u64
            } else {
                BorrowGeneration::None as u64
            }
        });

        let lut_does_block_generate_or_propagate =
            self.key.generate_lookup_table(|x| match x.cmp(&modulus) {
                Ordering::Less => BorrowGeneration::Generated as u64,
                Ordering::Equal => BorrowGeneration::Propagated as u64,
                Ordering::Greater => BorrowGeneration::None as u64,
            });

        let mut generates_or_propagates = Vec::with_capacity(sum_ct.blocks.len());
        sum_ct
            .blocks
            .par_iter()
            .enumerate()
            .map(|(i, block)| {
                if i == 0 {
                    // The first block can only output a borrow
                    self.key
                        .apply_lookup_table(block, &lut_does_block_generate_carry)
                } else {
                    self.key
                        .apply_lookup_table(block, &lut_does_block_generate_or_propagate)
                }
            })
            .collect_into_vec(&mut generates_or_propagates);

        generates_or_propagates
    }

    pub(crate) fn compute_borrow_propagation_parallelized_low_latency(
        &self,
        generates_or_propagates: Vec<Ciphertext>,
    ) -> (Vec<Ciphertext>, Ciphertext) {
        let lut_borrow_propagation_sum = self
            .key
            .generate_lookup_table_bivariate(prefix_sum_borrow_propagation);

        fn prefix_sum_borrow_propagation(msb: u64, lsb: u64) -> u64 {
            if msb == BorrowGeneration::Propagated as u64 {
                // We propagate the value of lsb
                lsb
            } else {
                msb
            }
        }

        // Type annotations are required, otherwise we get confusing errors
        // "implementation of `FnOnce` is not general enough"
        let sum_function = |block_carry: &mut Ciphertext, previous_block_carry: &Ciphertext| {
            self.key.unchecked_apply_lookup_table_bivariate_assign(
                block_carry,
                previous_block_carry,
                &lut_borrow_propagation_sum,
            );
        };

        let num_blocks = generates_or_propagates.len();

        let mut borrows_out =
            self.compute_prefix_sum_hillis_steele(generates_or_propagates, sum_function);
        let mut last_block_out_borrow = self.key.create_trivial(0);
        std::mem::swap(&mut borrows_out[num_blocks - 1], &mut last_block_out_borrow);
        // The output borrow of block i-1 becomes the input
        // borrow of block i
        borrows_out.rotate_right(1);
        self.key.create_trivial_assign(&mut borrows_out[0], 0);
        (borrows_out, last_block_out_borrow)
    }

    /// Computes the subtraction of two signed numbers and returns an indicator of overflow
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg_1 = i8::MIN;
    /// let msg_2 = 1;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt_signed(msg_1);
    /// let ctxt_2 = cks.encrypt_signed(msg_2);
    ///
    /// // Compute homomorphically a subtraction
    /// let (result, overflowed) = sks.signed_overflowing_sub_parallelized(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let decrypted_result: i8 = cks.decrypt_signed(&result);
    /// let decrypted_overflow = cks.decrypt_bool(&overflowed);
    ///
    /// let (expected_result, expected_overflow) = msg_1.overflowing_sub(msg_2);
    /// assert_eq!(expected_result, decrypted_result);
    /// assert_eq!(expected_overflow, decrypted_overflow);
    /// ```
    pub fn signed_overflowing_sub_parallelized(
        &self,
        ctxt_left: &SignedRadixCiphertext,
        ctxt_right: &SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let mut tmp_lhs;
        let mut tmp_rhs;

        let (lhs, rhs) = match (
            ctxt_left.block_carries_are_empty(),
            ctxt_right.block_carries_are_empty(),
        ) {
            (true, true) => (ctxt_left, ctxt_right),
            (true, false) => {
                tmp_rhs = ctxt_right.clone();
                self.full_propagate_parallelized(&mut tmp_rhs);
                (ctxt_left, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = ctxt_left.clone();
                self.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, ctxt_right)
            }
            (false, false) => {
                tmp_lhs = ctxt_left.clone();
                tmp_rhs = ctxt_right.clone();
                rayon::join(
                    || self.full_propagate_parallelized(&mut tmp_lhs),
                    || self.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        self.unchecked_signed_overflowing_sub_parallelized(lhs, rhs)
    }
}
