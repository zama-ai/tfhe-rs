use super::ServerKey;

use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::server_key::comparator::Comparator;

impl ServerKey {
    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_eq(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 == msg2));
    /// ```
    pub fn unchecked_eq(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x == y));
        let mut block_comparisons = lhs.blocks.clone();
        block_comparisons
            .iter_mut()
            .zip(rhs.blocks.iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;

        let is_max_value = self
            .key
            .generate_lookup_table(|x| u64::from((x & max_value as u64) == max_value as u64));

        while block_comparisons.len() > 1 {
            block_comparisons = block_comparisons
                .chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }

                    if blocks.len() == max_value {
                        self.key.apply_lookup_table(&sum, &is_max_value)
                    } else {
                        let is_equal_to_num_blocks = self.key.generate_lookup_table(|x| {
                            u64::from((x & max_value as u64) == blocks.len() as u64)
                        });
                        self.key.apply_lookup_table(&sum, &is_equal_to_num_blocks)
                    }
                })
                .collect::<Vec<_>>();
        }

        block_comparisons.resize_with(lhs.blocks.len(), || self.key.create_trivial(0));

        RadixCiphertext {
            blocks: block_comparisons,
        }
    }

    pub fn unchecked_ne(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        // Even though the corresponding function
        // may already exist in self.key
        // we generate our own lut to do less allocations
        let lut = self
            .key
            .generate_lookup_table_bivariate(|x, y| u64::from(x != y));
        let mut block_comparisons = lhs.blocks.clone();
        block_comparisons
            .iter_mut()
            .zip(rhs.blocks.iter())
            .for_each(|(lhs_block, rhs_block)| {
                self.key
                    .unchecked_apply_lookup_table_bivariate_assign(lhs_block, rhs_block, &lut);
            });

        let message_modulus = self.key.message_modulus.0;
        let carry_modulus = self.key.carry_modulus.0;
        let total_modulus = message_modulus * carry_modulus;
        let max_value = total_modulus - 1;
        let is_non_zero = self.key.generate_lookup_table(|x| u64::from(x != 0));

        while block_comparisons.len() > 1 {
            block_comparisons = block_comparisons
                .chunks(max_value)
                .map(|blocks| {
                    let mut sum = blocks[0].clone();
                    for other_block in &blocks[1..] {
                        self.key.unchecked_add_assign(&mut sum, other_block);
                    }
                    self.key.apply_lookup_table(&sum, &is_non_zero)
                })
                .collect::<Vec<_>>();
        }

        block_comparisons.resize_with(lhs.blocks.len(), || self.key.create_trivial(0));

        RadixCiphertext {
            blocks: block_comparisons,
        }
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs > rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_gt(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 > msg2));
    /// ```
    pub fn unchecked_gt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_gt(lhs, rhs)
    }

    /// Compares if lhs is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs >= rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 97u64;
    /// let msg2 = 97u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_ge(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 >= msg2));
    /// ```
    pub fn unchecked_ge(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_ge(lhs, rhs)
    }

    /// Compares if lhs is strictly lower than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_lt(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn unchecked_lt(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_lt(lhs, rhs)
    }

    /// Compares if lhs is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_le(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn unchecked_le(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_le(lhs, rhs)
    }

    /// Computes the max of two encrypted values
    ///
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_max(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::max(msg1, msg2));
    /// ```
    pub fn unchecked_max(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_max(lhs, rhs)
    }

    /// Computes the min of two encrypted values
    ///
    ///
    /// Requires carry bits to be empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 237u64;
    /// let msg2 = 23u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.unchecked_min(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::min(msg1, msg2));
    /// ```
    pub fn unchecked_min(&self, lhs: &RadixCiphertext, rhs: &RadixCiphertext) -> RadixCiphertext {
        Comparator::new(self).unchecked_min(lhs, rhs)
    }

    /// Compares for equality 2 ciphertexts
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_eq(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 == msg2));
    /// ```
    pub fn smart_eq(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate(rhs);
        }
        self.unchecked_eq(lhs, rhs)
    }

    pub fn smart_ne(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        if !lhs.block_carries_are_empty() {
            self.full_propagate(lhs);
        }
        if !rhs.block_carries_are_empty() {
            self.full_propagate(rhs);
        }
        self.unchecked_ne(lhs, rhs)
    }

    /// Compares if lhs is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs == rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_gt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 > msg2));
    /// ```
    pub fn smart_gt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_gt(lhs, rhs)
    }

    /// Compares if lhs is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs >= rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_gt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 >= msg2));
    /// ```
    pub fn smart_ge(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_ge(lhs, rhs)
    }

    /// Compares if lhs is strictly lower than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_lt(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 < msg2));
    /// ```
    pub fn smart_lt(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_lt(lhs, rhs)
    }

    /// Compares if lhs is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if lhs <= rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_le(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, u64::from(msg1 <= msg2));
    /// ```
    pub fn smart_le(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_le(lhs, rhs)
    }

    /// Computes the max of two encrypted values
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_max(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::max(msg1, msg2));
    /// ```
    pub fn smart_max(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_max(lhs, rhs)
    }

    /// Computes the min of two encrypted values
    ///
    /// Returns a ciphertext containing 1 if lhs < rhs, otherwise 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 14u64;
    /// let msg2 = 97u64;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_min(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, std::cmp::min(msg1, msg2));
    /// ```
    pub fn smart_min(
        &self,
        lhs: &mut RadixCiphertext,
        rhs: &mut RadixCiphertext,
    ) -> RadixCiphertext {
        Comparator::new(self).smart_min(lhs, rhs)
    }
}
