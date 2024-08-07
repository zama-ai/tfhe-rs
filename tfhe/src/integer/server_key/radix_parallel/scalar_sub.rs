use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::server_key::radix::scalar_sub::TwosComplementNegation;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};

impl ServerKey {
    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.smart_scalar_sub_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn smart_scalar_sub_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_sub_possible(ct, scalar).unwrap();
        self.unchecked_scalar_sub(ct, scalar)
    }

    pub fn smart_scalar_sub_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if self.is_scalar_sub_possible(ct, scalar).is_err() {
            self.full_propagate_parallelized(ct);
        }
        self.is_scalar_sub_possible(ct, scalar).unwrap();
        self.unchecked_scalar_sub_assign(ct, scalar);
    }

    /// Computes homomorphically a subtraction of a ciphertext by a scalar.
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
    /// let msg = 165;
    /// let scalar = 112;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.scalar_sub_parallelized(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn scalar_sub_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        let mut ct_res = ct.clone();
        self.scalar_sub_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    pub fn scalar_sub_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        T: IntegerRadixCiphertext,
        Scalar: TwosComplementNegation + DecomposableInto<u8>,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_parallelized(ct);
        };

        if Scalar::ZERO == scalar {
            return;
        }

        self.scalar_add_assign_parallelized(ct, scalar.twos_complement_negation());
    }

    pub fn unsigned_overflowing_scalar_sub_assign_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: T,
    ) -> BooleanBlock
    where
        T: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = T>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        let mut scalar_decomposer =
            BlockDecomposer::new(scalar, self.message_modulus().0.ilog2()).iter_as::<u8>();

        lhs.blocks
            .iter_mut() // Not worth to parallelize
            .zip(scalar_decomposer.by_ref())
            .for_each(|(lhs_block, rhs_scalar)| {
                self.key
                    .unchecked_scalar_sub_assign_with_correcting_term(lhs_block, rhs_scalar)
            });
        let overflowed = self.unsigned_overflowing_propagate_subtraction_borrow(lhs);

        let is_there_any_non_zero_scalar_blocks_left = scalar_decomposer.any(|x| x != 0);
        if is_there_any_non_zero_scalar_blocks_left {
            // Scalar has more blocks so subtraction counts as overflowing
            BooleanBlock::new_unchecked(self.key.create_trivial(1))
        } else {
            overflowed
        }
    }

    pub fn unsigned_overflowing_scalar_sub_parallelized<T>(
        &self,
        lhs: &RadixCiphertext,
        scalar: T,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        T: UnsignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = T>,
    {
        let mut result = lhs.clone();
        let overflow =
            self.unsigned_overflowing_scalar_sub_assign_parallelized(&mut result, scalar);
        (result, overflow)
    }

    pub fn signed_overflowing_scalar_sub_assign_parallelized<Scalar>(
        &self,
        lhs: &mut SignedRadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: SignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        if !lhs.block_carries_are_empty() {
            self.full_propagate_parallelized(lhs);
        }

        // The trivial overflow check has to be done on the scalar not its bit flipped version
        let mut decomposer = BlockDecomposer::new(scalar, self.message_modulus().0.ilog2())
            .iter_as::<u8>()
            .skip(lhs.blocks.len());

        let trivially_overflowed = if scalar < Scalar::ZERO {
            decomposer.any(|v| v != (self.message_modulus().0 - 1) as u8)
        } else {
            decomposer.any(|v| v != 0)
        };

        const INPUT_CARRY: bool = true;
        let flipped_scalar = !scalar;
        let decomposed_flipped_scalar =
            BlockDecomposer::new(flipped_scalar, self.message_modulus().0.ilog2())
                .iter_as::<u8>()
                .chain(std::iter::repeat(if scalar < Scalar::ZERO {
                    0
                } else {
                    (self.message_modulus().0 - 1) as u8
                }))
                .take(lhs.blocks.len())
                .collect::<Vec<_>>();
        let maybe_overflow = self.add_assign_scalar_blocks_parallelized(
            lhs,
            decomposed_flipped_scalar,
            INPUT_CARRY,
            !trivially_overflowed,
        );

        if trivially_overflowed {
            self.create_trivial_boolean_block(true)
        } else {
            maybe_overflow.expect("overflow computation was requested")
        }
    }

    pub fn signed_overflowing_scalar_sub_parallelized<Scalar>(
        &self,
        lhs: &SignedRadixCiphertext,
        scalar: Scalar,
    ) -> (SignedRadixCiphertext, BooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u8> + std::ops::Not<Output = Scalar>,
    {
        let mut result = lhs.clone();
        let overflow = self.signed_overflowing_scalar_sub_assign_parallelized(&mut result, scalar);
        (result, overflow)
    }
}
