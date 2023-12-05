use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::{IntegerRadixCiphertext, RadixCiphertext};
use crate::integer::server_key::CheckError;
use crate::integer::ServerKey;

pub trait TwosComplementNegation {
    fn twos_complement_negation(self) -> Self;
}

impl<T> TwosComplementNegation for T
where
    T: Numeric + std::ops::Not<Output = Self> + std::ops::Add<Self, Output = Self>,
{
    fn twos_complement_negation(self) -> Self {
        let flipped = !self;
        flipped + Self::ONE
    }
}

impl ServerKey {
    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.unchecked_scalar_sub(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn unchecked_scalar_sub<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        let mut result = ct.clone();
        self.unchecked_scalar_sub_assign(&mut result, scalar);
        result
    }

    // Creates an iterator that return decomposed blocks of the negated
    // value of `scalar`
    //
    // Returns
    // - `None` if scalar is zero
    // - `Some` if scalar is non-zero
    //
    fn create_negated_block_decomposer<Scalar>(
        &self,
        scalar: Scalar,
    ) -> Option<impl Iterator<Item = u8>>
    where
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if scalar == Scalar::ZERO {
            return None;
        }
        let bits_in_message = self.key.message_modulus.0.ilog2();
        assert!(bits_in_message <= u8::BITS);

        // The whole idea behind this iterator we construct is:
        // - to support combos of parameters and num blocks for which the total number of bits is
        //   not a multiple of T::BITS
        //
        // - Support subtraction in the case the T::BITS is lower than the target ciphertext bits.
        //   In clear rust this would require an upcast, to support that we have to do a few things

        let neg_scalar = scalar.twos_complement_negation();

        // If we had upcasted the scalar, its msb would be zeros (0)
        // then they would become ones (1) after the bitwise_not (!).
        // The only case where these msb could become 0 after the addition
        // is if scalar == T::ZERO (=> !T::ZERO == T::MAX => T::MAX + 1 == overflow),
        // but this case has been handled earlier.
        let padding_bit = 1u32; // To handle when bits is not a multiple of T::BITS
                                // All bits of message set to one
        let pad_block = (1 << bits_in_message as u8) - 1;

        let decomposer = BlockDecomposer::with_padding_bit(
            neg_scalar,
            bits_in_message,
            Scalar::cast_from(padding_bit),
        )
        .iter_as::<u8>()
        .chain(std::iter::repeat(pad_block));
        Some(decomposer)
    }

    pub fn unchecked_scalar_sub_assign<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        let Some(decomposer) = self.create_negated_block_decomposer(scalar) else {
            // subtraction by zero
            return;
        };
        for (ciphertext_block, scalar_block) in ct.blocks_mut().iter_mut().zip(decomposer) {
            self.key
                .unchecked_scalar_add_assign(ciphertext_block, scalar_block);
        }
    }

    /// Verifies if the subtraction of a ciphertext by scalar can be computed.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::integer::gen_keys_radix;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 40u64;
    /// let scalar = 2u64;
    ///
    /// let ct1 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an addition
    /// sks.is_scalar_sub_possible(&ct1, scalar).unwrap();
    /// ```
    pub fn is_scalar_sub_possible<T, Scalar>(
        &self,
        ct: &T,
        scalar: Scalar,
    ) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        let Some(decomposer) = self.create_negated_block_decomposer(scalar) else {
            // subtraction by zero
            return Ok(());
        };
        ct.blocks()
            .iter()
            .zip(decomposer)
            .try_for_each(|(ciphertext_block, scalar_block)| {
                // The decomposer gives the block of the negated
                // scalar (-scalar) that we will be adding
                self.key
                    .is_scalar_add_possible(ciphertext_block.noise_degree(), scalar_block)
            })
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 40;
    /// let scalar = 4;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute the subtraction:
    /// let ct_res = sks.checked_scalar_sub(&ct, scalar)?;
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_scalar_sub<T, Scalar>(&self, ct: &T, scalar: Scalar) -> Result<T, CheckError>
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        self.is_scalar_sub_possible(ct, scalar)?;
        Ok(self.unchecked_scalar_sub(ct, scalar))
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    ///
    /// let msg = 232;
    /// let scalar = 83;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute the subtraction:
    /// sks.checked_scalar_sub_assign(&mut ct, scalar)?;
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg - scalar, dec);
    /// # Ok(())
    /// # }
    /// ```
    pub fn checked_scalar_sub_assign<T, Scalar>(
        &self,
        ct: &mut T,
        scalar: Scalar,
    ) -> Result<(), CheckError>
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        self.is_scalar_sub_possible(ct, scalar)?;
        self.unchecked_scalar_sub_assign(ct, scalar);
        Ok(())
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_sub(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn smart_scalar_sub<T, Scalar>(&self, ct: &mut T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate(ct);
        }

        self.is_scalar_sub_possible(ct, scalar).unwrap();

        self.unchecked_scalar_sub(ct, scalar)
    }

    pub fn smart_scalar_sub_assign<T, Scalar>(&self, ct: &mut RadixCiphertext, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate(ct);
        }

        self.is_scalar_sub_possible(ct, scalar).unwrap();

        self.unchecked_scalar_sub_assign(ct, scalar);
    }
}
