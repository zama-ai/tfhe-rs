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

        self.unchecked_scalar_sub_assign(ct, scalar);

        if self.is_eligible_for_parallel_single_carry_propagation(ct) {
            let _carry = self.propagate_single_carry_parallelized_low_latency(ct);
        } else {
            self.full_propagate_parallelized(ct);
        }
    }

    pub fn unsigned_overflowing_scalar_sub_assign_parallelized<T>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: T,
    ) -> BooleanBlock
    where
        T: UnsignedNumeric + DecomposableInto<u8>,
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
        T: UnsignedNumeric + DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        let overflowed =
            self.unsigned_overflowing_scalar_sub_assign_parallelized(&mut result, scalar);
        (result, overflowed)
    }

    pub fn signed_overflowing_scalar_sub_parallelized<Scalar>(
        &self,
        lhs: &SignedRadixCiphertext,
        scalar: Scalar,
    ) -> (SignedRadixCiphertext, BooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u64>,
    {
        // In this implementation, we cannot simply call
        // signed_overflowing_scalar_add_parallelized(lhs, -scalar)
        // because in the case scalar == -modulus (i.e the minimum value of the ciphertext type)
        // then -rhs will still be -modulus, however, the overflow detection of the add
        // will be invalid

        let mut tmp_lhs;
        let lhs = if lhs.block_carries_are_empty() {
            lhs
        } else {
            tmp_lhs = lhs.clone();
            self.full_propagate_parallelized(&mut tmp_lhs);
            &tmp_lhs
        };

        // To keep the code simple we transform the scalar into a trivial
        // performances wise this won't have much impact as all the cost is
        // in the carry propagation
        let trivial: SignedRadixCiphertext = self.create_trivial_radix(scalar, lhs.blocks.len());
        let (result, overflowed) = self.signed_overflowing_sub_parallelized(lhs, &trivial);

        let mut extra_scalar_block_iter =
            BlockDecomposer::new(scalar, self.key.message_modulus.0.ilog2())
                .iter_as::<u64>()
                .skip(lhs.blocks.len());

        let extra_blocks_have_correct_value = if scalar < Scalar::ZERO {
            extra_scalar_block_iter.all(|block| block == (self.message_modulus().0 as u64 - 1))
        } else {
            extra_scalar_block_iter.all(|block| block == 0)
        };

        if extra_blocks_have_correct_value {
            (result, overflowed)
        } else {
            // Scalar has more blocks so addition counts as overflowing
            (
                result,
                BooleanBlock::new_unchecked(self.key.create_trivial(1)),
            )
        }
    }
}
