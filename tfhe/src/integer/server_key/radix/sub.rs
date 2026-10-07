use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;
use crate::shortint::ciphertext::{Degree, MaxDegree, NoiseLevel};

impl ServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg_1 = 12;
    /// let msg_2 = 10;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.unchecked_sub(&ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub<T>(&self, ctxt_left: &T, ctxt_right: &T) -> T
    where
        T: IntegerRadixCiphertext,
    {
        let mut result = ctxt_left.clone();
        self.unchecked_sub_assign(&mut result, ctxt_right);
        result
    }

    /// Computes homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// This function computes the subtraction without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg_1 = 128;
    /// let msg_2 = 99;
    ///
    /// // Encrypt two messages:
    /// let mut ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.unchecked_sub_assign(&mut ctxt_1, &ctxt_2);
    ///
    /// // Decrypt:
    /// let dec_result: u64 = cks.decrypt(&ctxt_1);
    /// assert_eq!(dec_result, msg_1 - msg_2);
    /// ```
    pub fn unchecked_sub_assign<T>(&self, ctxt_left: &mut T, ctxt_right: &T)
    where
        T: IntegerRadixCiphertext,
    {
        let neg = self.unchecked_neg(ctxt_right);
        self.unchecked_add_assign(ctxt_left, &neg);
    }

    /// Verifies if ct_right can be subtracted to ct_left.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, num_blocks);
    ///
    /// let msg_1 = 182u64;
    /// let msg_2 = 120u64;
    ///
    /// // Encrypt two messages:
    /// let ctxt_1 = cks.encrypt(msg_1);
    /// let ctxt_2 = cks.encrypt(msg_2);
    ///
    /// // Check if we can perform a subtraction
    /// sks.is_sub_possible(&ctxt_1, &ctxt_2).unwrap();
    /// ```
    pub fn is_sub_possible<T>(&self, ctxt_left: &T, ctxt_right: &T) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
    {
        let mut preceding_block_carry = Degree::new(0);
        let mut preceding_scaled_z = 0;
        let mut extracted_carry_noise_level = NoiseLevel::ZERO;
        for (left_block, right_block) in ctxt_left.blocks().iter().zip(ctxt_right.blocks().iter()) {
            // Assumes message_modulus and carry_modulus matches between pairs of block
            let msg_mod = left_block.message_modulus.0;
            let max_degree = MaxDegree::from_msg_carry_modulus(
                left_block.message_modulus,
                left_block.carry_modulus,
            );

            // z = ceil( degree / 2^p ) x 2^p
            let mut z = right_block.degree.get().div_ceil(msg_mod);
            z = z.wrapping_mul(msg_mod);
            // In the actual operation, preceding_scaled_z is added to the ciphertext
            // before doing lwe_ciphertext_opposite:
            // i.e the code does -(ciphertext + preceding_scaled_z) + z
            // here we do -ciphertext -preceding_scaled_z + z
            // which is easier to express degree
            let right_block_degree_after_negation = Degree::new(z - preceding_scaled_z);

            let degree_after_add = left_block.degree + right_block_degree_after_negation;

            // We want to be able to add the left block, the negated right block
            // and we also want to be able to add the carry from preceding block addition
            // to make sure carry propagation would be correct.
            max_degree.validate(degree_after_add + preceding_block_carry)?;

            self.key.max_noise_level.validate(
                left_block.noise_level() + right_block.noise_level() + extracted_carry_noise_level,
            )?;

            preceding_block_carry = Degree::new(degree_after_add.get() / msg_mod);
            preceding_scaled_z = z / msg_mod;
            extracted_carry_noise_level = NoiseLevel::NOMINAL;
        }
        Ok(())
    }
}
