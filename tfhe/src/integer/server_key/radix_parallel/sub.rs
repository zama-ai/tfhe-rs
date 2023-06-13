use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::ServerKey;

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
    pub fn smart_sub_parallelized(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

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
    pub fn smart_sub_assign_parallelized(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &mut RadixCiphertext,
    ) {
        // If the ciphertext cannot be negated without exceeding the capacity of a ciphertext
        if !self.is_neg_possible(ctxt_right) {
            self.full_propagate_parallelized(ctxt_right);
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !self.is_sub_possible(ctxt_left, ctxt_right) {
            rayon::join(
                || self.full_propagate_parallelized(ctxt_left),
                || self.full_propagate_parallelized(ctxt_right),
            );
        }

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
    pub fn sub_parallelized(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> RadixCiphertext {
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
    pub fn sub_assign_parallelized(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) {
        let mut tmp_rhs: RadixCiphertext;

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

        if self.is_eligible_for_parallel_carryless_add() {
            let neg = self.unchecked_neg(rhs);
            self.unchecked_add_assign_parallelized_low_latency(lhs, &neg);
        } else {
            self.unchecked_sub_assign(lhs, rhs);
            self.full_propagate_parallelized(lhs);
        }
    }

    pub fn sub_parallelized_work_efficient(
        &self,
        ctxt_left: &RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) -> RadixCiphertext {
        let mut ct_res = ctxt_left.clone();
        self.sub_assign_parallelized_work_efficient(&mut ct_res, ctxt_right);
        ct_res
    }

    pub fn sub_assign_parallelized_work_efficient(
        &self,
        ctxt_left: &mut RadixCiphertext,
        ctxt_right: &RadixCiphertext,
    ) {
        let mut tmp_rhs: RadixCiphertext;

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
        self.unchecked_add_assign_parallelized_work_efficient(lhs, &neg);
    }
}
