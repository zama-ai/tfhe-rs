use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, ServerKey};
use crate::shortint::CheckError;

impl ServerKey {
    /// Computes homomorphically bitand between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let msg1 = 201u64;
    /// let msg2 = 1u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise and:
    /// let ct_res = sks.unchecked_bitand(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 & msg2);
    /// ```
    pub fn unchecked_bitand<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitand_assign<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        for (ct_left_i, ct_right_i) in ct_left
            .blocks_mut()
            .iter_mut()
            .zip(ct_right.blocks().iter())
        {
            self.key.unchecked_bitand_assign(ct_left_i, ct_right_i);
        }
    }

    /// Verifies if a bivariate functional pbs can be applied on ct_left and ct_right.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let size = 4;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg1 = 46u64;
    /// let msg2 = 87u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let res = sks
    ///     .is_functional_bivariate_pbs_possible(&ct1, &ct2)
    ///     .unwrap();
    /// ```
    pub fn is_functional_bivariate_pbs_possible<T>(
        &self,
        ct_left: &T,
        ct_right: &T,
    ) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        for (ct_left_i, ct_right_i) in ct_left.blocks().iter().zip(ct_right.blocks().iter()) {
            self.key.is_functional_bivariate_pbs_possible(
                ct_left_i.noise_degree(),
                ct_right_i.noise_degree(),
            )?;
        }
        Ok(())
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.checked_bitand(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 & msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitand<T>(&self, ct_left: &T, ct_right: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        Ok(self.unchecked_bitand(ct_left, ct_right))
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// sks.checked_bitand_assign(&mut ct1, &ct2).unwrap();
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 & msg2, clear);
    /// ```
    pub fn checked_bitand_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        self.unchecked_bitand_assign(ct_left, ct_right);
        Ok(())
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
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
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitand(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 & msg2);
    /// ```
    pub fn smart_bitand<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitand(ct_left, ct_right)
    }

    pub fn smart_bitand_assign<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitand_assign(ct_left, ct_right);
    }

    /// Computes homomorphically bitor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let msg1 = 200;
    /// let msg2 = 1;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise or:
    /// let ct_res = sks.unchecked_bitor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec, msg1 | msg2);
    /// ```
    pub fn unchecked_bitor<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitor_assign<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        for (ct_left_i, ct_right_i) in ct_left
            .blocks_mut()
            .iter_mut()
            .zip(ct_right.blocks().iter())
        {
            self.key.unchecked_bitor_assign(ct_left_i, ct_right_i);
        }
    }

    /// Computes homomorphically a bitor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_bitor(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 | msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitor<T>(&self, ct_left: &T, ct_right: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        Ok(self.unchecked_bitor(ct_left, ct_right))
    }

    /// Computes homomorphically a bitand between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.checked_bitor_assign(&mut ct1, &ct2).unwrap();
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 | msg2, clear);
    /// ```
    pub fn checked_bitor_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        self.unchecked_bitor_assign(ct_left, ct_right);
        Ok(())
    }

    /// Computes homomorphically a bitor between two ciphertexts encrypting integer values.
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
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 | msg2);
    /// ```
    pub fn smart_bitor<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitor(ct_left, ct_right)
    }

    pub fn smart_bitor_assign<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitor_assign(ct_left, ct_right);
    }

    /// Computes homomorphically bitxor between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
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
    /// let msg1 = 49;
    /// let msg2 = 64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically a bitwise xor:
    /// let ct_res = sks.unchecked_bitxor(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg1 ^ msg2, dec);
    /// ```
    pub fn unchecked_bitxor<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(&mut result, ct_right);
        result
    }

    pub fn unchecked_bitxor_assign<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        for (ct_left_i, ct_right_i) in ct_left
            .blocks_mut()
            .iter_mut()
            .zip(ct_right.blocks().iter())
        {
            self.key.unchecked_bitxor_assign(ct_left_i, ct_right_i);
        }
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_bitxor(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 ^ msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_bitxor<T>(&self, ct_left: &T, ct_right: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        Ok(self.unchecked_bitxor(ct_left, ct_right))
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
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
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.checked_bitxor_assign(&mut ct1, &ct2).unwrap();
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 ^ msg2, clear);
    /// ```
    pub fn checked_bitxor_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)?;
        self.unchecked_bitxor_assign(ct_left, ct_right);
        Ok(())
    }

    /// Computes homomorphically a bitxor between two ciphertexts encrypting integer values.
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
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// let ct_res = sks.smart_bitxor(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 ^ msg2);
    /// ```
    pub fn smart_bitxor<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitxor(ct_left, ct_right)
    }

    pub fn smart_bitxor_assign<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();
        self.unchecked_bitxor_assign(ct_left, ct_right);
    }

    /// Computes homomorphically a bitand between two boolean ciphertexts
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// let ct_is_ge = sks.scalar_ge_parallelized(&ct, 10);
    /// let ct_is_le = sks.scalar_le_parallelized(&ct, 15);
    ///
    /// let ct_is_in_range = sks.boolean_bitand(&ct_is_ge, &ct_is_le);
    ///
    /// // Decrypt:
    /// let dec_result = cks.decrypt_bool(&ct_is_in_range);
    /// assert_eq!(dec_result, msg >= 10 && msg <= 15);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let mut ct = cks.encrypt(msg);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 14u8;
    ///
    /// let mut ct = cks.encrypt(msg);
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
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
        let result = self.key.scalar_bitxor(&boolean_block.0, 1);
        BooleanBlock::new_unchecked(result)
    }
    pub fn boolean_bitnot_assign(&self, boolean_block: &mut BooleanBlock) {
        self.key.scalar_bitxor_assign(&mut boolean_block.0, 1);
    }
}
