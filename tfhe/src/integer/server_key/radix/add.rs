use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;
use crate::shortint::ciphertext::{Degree, MaxDegree, NoiseLevel};

impl ServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 10;
    /// let msg2 = 127;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_add(&ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn unchecked_add<T>(&self, ct_left: &T, ct_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ct_left.clone();
        self.unchecked_add_assign(&mut result, ct_right);
        result
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 28;
    /// let msg2 = 127;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.unchecked_add_assign(&mut ct1, &ct2);
    ///
    /// // Decrypt:
    /// let dec_ct1: u64 = cks.decrypt(&ct1);
    /// assert_eq!(dec_ct1, msg1 + msg2);
    /// ```
    pub fn unchecked_add_assign<T>(&self, ct_left: &mut T, ct_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        for (ct_left_i, ct_right_i) in ct_left
            .blocks_mut()
            .iter_mut()
            .zip(ct_right.blocks().iter())
        {
            self.key.unchecked_add_assign(ct_left_i, ct_right_i);
        }
    }

    /// Verifies if ct1 and ct2 can be added together.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 46u64;
    /// let msg2 = 87u64;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Check if we can perform an addition
    /// sks.is_add_possible(&ct1, &ct2).unwrap();
    /// ```
    pub fn is_add_possible<T>(&self, ct_left: &T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        // Assumes message_modulus and carry_modulus matches between pairs of block
        let mut preceding_block_carry = Degree::new(0);
        let mut extracted_carry_noise_level = NoiseLevel::ZERO;
        for (left_block, right_block) in ct_left.blocks().iter().zip(ct_right.blocks().iter()) {
            let degree_after_add = left_block.degree + right_block.degree;

            // Also need to take into account preceding_carry

            let max_degree = MaxDegree::from_msg_carry_modulus(
                left_block.message_modulus,
                left_block.carry_modulus,
            );

            max_degree.validate(degree_after_add + preceding_block_carry)?;

            self.key.max_noise_level.validate(
                left_block.noise_level() + right_block.noise_level() + extracted_carry_noise_level,
            )?;

            preceding_block_carry =
                Degree::new(degree_after_add.get() / left_block.message_modulus.0);
            extracted_carry_noise_level = NoiseLevel::NOMINAL;
        }
        Ok(())
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_add(&ct1, &ct2);
    ///
    /// match ct_res {
    ///     Err(x) => panic!("{:?}", x),
    ///     Ok(y) => {
    ///         let clear: u64 = cks.decrypt(&y);
    ///         assert_eq!(msg1 + msg2, clear);
    ///     }
    /// }
    /// ```
    pub fn checked_add<T>(&self, ct_left: &T, ct_right: &T) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_add_possible(ct_left, ct_right)?;
        Ok(self.unchecked_add(ct_left, ct_right))
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg1 = 41;
    /// let msg2 = 101;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// sks.checked_add_assign(&mut ct1, &ct2).unwrap();
    ///
    /// let clear: u64 = cks.decrypt(&ct1);
    /// assert_eq!(msg1 + msg2, clear);
    /// ```
    pub fn checked_add_assign<T>(&self, ct_left: &mut T, ct_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        self.is_add_possible(ct_left, ct_right)?;
        self.unchecked_add_assign(ct_left, ct_right);
        Ok(())
    }

    /// Computes homomorphically an addition between two ciphertexts encrypting integer values.
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
    /// let msg1 = 14;
    /// let msg2 = 97;
    ///
    /// let mut ct1 = cks.encrypt(msg1);
    /// let mut ct2 = cks.encrypt(msg2);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_add(&mut ct1, &mut ct2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg1 + msg2);
    /// ```
    pub fn smart_add<T>(&self, ct_left: &mut T, ct_right: &mut T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        if self.is_add_possible(ct_left, ct_right).is_err() {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }

        self.is_add_possible(ct_left, ct_right).unwrap();
        self.unchecked_add(ct_left, ct_right)
    }

    pub fn smart_add_assign<T>(&self, ct_left: &mut T, ct_right: &mut T)
    where
        T: IntegerRadixCiphertext,
    {
        //If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.is_add_possible(ct_left, ct_right).is_err() {
            self.full_propagate(ct_left);
            self.full_propagate(ct_right);
        }
        self.is_add_possible(ct_left, ct_right).unwrap();

        self.unchecked_add_assign(ct_left, ct_right);
    }
}
