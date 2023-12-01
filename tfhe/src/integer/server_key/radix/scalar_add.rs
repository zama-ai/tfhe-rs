use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;
use crate::shortint::ciphertext::{Degree, MaxDegree};

impl ServerKey {
    /// Computes homomorphically an addition between a scalar and a ciphertext.
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
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_add(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn unchecked_scalar_add<T, C>(&self, ct: &C, scalar: T) -> C
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_add_assign(&mut result, scalar);
        result
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    pub fn unchecked_scalar_add_assign<T, C>(&self, ct: &mut C, scalar: T)
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        let bits_in_message = self.key.message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        for (ciphertext_block, scalar_block) in ct.blocks_mut().iter_mut().zip(decomposer) {
            self.key
                .unchecked_scalar_add_assign(ciphertext_block, scalar_block);
        }
    }

    /// Verifies if a scalar can be added to a ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 2u64;
    /// let scalar = 40;
    ///
    /// // Encrypt two messages:
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// sks.is_scalar_add_possible(&ct1, scalar).unwrap();
    /// ```
    pub fn is_scalar_add_possible<T, C>(&self, ct: &C, scalar: T) -> Result<(), CheckError>
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        let bits_in_message = self.key.message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();

        // Assumes message_modulus and carry_modulus matches between pairs of block
        let mut preceding_block_carry = Degree::new(0);
        for (left_block, scalar_block_value) in ct.blocks().iter().zip(decomposer) {
            let degree_after_add = left_block.degree + Degree::new(scalar_block_value as usize);

            // Also need to take into account preceding_carry
            let max_degree = MaxDegree::from_msg_carry_modulus(
                left_block.message_modulus,
                left_block.carry_modulus,
            );

            max_degree.validate(degree_after_add + preceding_block_carry)?;

            preceding_block_carry =
                Degree::new(degree_after_add.get() / left_block.message_modulus.0);
        }
        Ok(())
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is returned in a new ciphertext.
    /// Otherwise a [CheckError] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.checked_scalar_add(&mut ct, scalar)?;
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_scalar_add<T, C>(&self, ct: &C, scalar: T) -> Result<C, CheckError>
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        self.is_scalar_add_possible(ct, scalar)?;
        Ok(self.unchecked_scalar_add(ct, scalar))
    }

    /// Computes homomorphically an addition between a scalar and a ciphertext.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise a [CheckError] is returned, and `ct_left` is not modified.
    pub fn checked_scalar_add_assign<T, C>(&self, ct: &mut C, scalar: T) -> Result<(), CheckError>
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        self.is_scalar_add_possible(ct, scalar)?;
        self.unchecked_scalar_add_assign(ct, scalar);
        Ok(())
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
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
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_add(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add<T, C>(&self, ct: &mut C, scalar: T) -> C
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        if self.is_scalar_add_possible(ct, scalar).is_err() {
            self.full_propagate(ct);
        }

        self.is_scalar_add_possible(ct, scalar).unwrap();

        let mut ct = ct.clone();
        self.unchecked_scalar_add_assign(&mut ct, scalar);
        ct
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
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
    /// let msg = 129;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.smart_scalar_add_assign(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn smart_scalar_add_assign<T, C>(&self, ct: &mut C, scalar: T)
    where
        T: DecomposableInto<u8>,
        C: IntegerRadixCiphertext,
    {
        if self.is_scalar_add_possible(ct, scalar).is_err() {
            self.full_propagate(ct);
        }
        self.is_scalar_add_possible(ct, scalar).unwrap();
        self.unchecked_scalar_add_assign(ct, scalar);
    }
}
