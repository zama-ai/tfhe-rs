use crate::core_crypto::prelude::{SignedNumeric, UnsignedNumeric};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::ciphertext::IntegerRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey, SignedRadixCiphertext};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::Ciphertext;

use rayon::prelude::*;

/// How the overflow flag of an overflowing scalar addition or subtraction is obtained.
///
/// Decided from the scalar alone, see [`Self::for_signed_radix`] and
/// [`Self::for_unsigned_radix`].
///
/// Only the flag is concerned: the FHE operation works on the scalar truncated to the radix
/// width, which is congruent to the scalar modulo the radix modulus, so the result it
/// computes is the exact one reduced to the radix width whatever the scalar, with nothing to
/// accommodate. With `n` the radix bit width and `s'` the truncated scalar:
///
/// `s' ≡ s (mod 2ⁿ)  ⇒  lhs ± s' ≡ lhs ± s (mod 2ⁿ)`
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ScalarOverflowFlagSource {
    /// The scalar is beyond what the radix blocks can hold: the operation always overflows
    TriviallyTrue,
    /// The scalar fits the radix blocks but not the radix range: the FHE flag is the opposite
    /// of the exact one
    InvertedFhe,
    /// The scalar is in the radix range: the FHE flag is exact
    Fhe,
}

impl ScalarOverflowFlagSource {
    /// Decides how the overflow flag of an overflowing scalar addition or subtraction between
    /// a signed radix of `num_blocks` blocks of `message_modulus` and `scalar` is obtained.
    ///
    /// The FHE operation only sees the scalar truncated to the radix's block count. This
    /// means the scalar value the FHE operation will see may not be interpreted 'correctly'
    /// and the flag may need to be inverted; the result is correct either way, see
    /// [`ScalarOverflowFlagSource`].
    ///
    /// This contains the logic to figure out how to handle this situation, as well as the
    /// explanations to convince it's correct.
    ///
    /// The explanations in the code are made for the subtraction, but the same logic
    /// and principles apply for the addition.
    pub(crate) fn for_signed_radix<Scalar>(
        scalar: Scalar,
        num_blocks: usize,
        message_modulus: MessageModulus,
    ) -> Self
    where
        Scalar: DecomposableInto<u8>,
    {
        assert!(num_blocks > 0, "input radix must not be empty");

        // The check is done on the scalar itself, not on the bit flipped version the
        // subtraction adds
        let mut decomposer = BlockDecomposer::new(scalar, message_modulus.0.ilog2())
            .iter_as::<u8>()
            .skip(num_blocks - 1);

        if scalar < Scalar::ZERO {
            let sign_bit_is_not_set = decomposer.next().is_some_and(|v| {
                let sign_bit = v as u64 / (message_modulus.0 / 2);
                sign_bit == 0
            });
            let top_is_not_all_sign_bit = decomposer.any(|v| v != (message_modulus.0 - 1) as u8);

            if top_is_not_all_sign_bit {
                Self::TriviallyTrue
            } else if sign_bit_is_not_set {
                // (With `n` the radix bit width)
                //
                // The clear is negative, bits above the radix width are all sign bits.
                // However, the bit that is at the position of the radix's sign bit is 0.
                // This means the clear `s` has a value in the range `[-2ⁿ, -2ⁿ⁻¹[`
                // or (`[-2ⁿ, -2ⁿ⁻¹ - 1]`)
                // e.g: signed radix of 8 bits (n=8), clear of 16 bits, under these conditions,
                // the clear is in `[-256, -128[` (or `[-256, -129]`)
                //
                // But since the overflowing_sub done later will only see the truncated version
                // of the clear, it will see a number `s'` in the range `[0, 2ⁿ⁻¹[`
                // i.e it will see `s' = s + 2ⁿ`
                // e.g: taking the example before, the scalar was in `[-256, -128[`, the truncated
                // version given to the FHE op will be interpreted as `[-256 + 256, -128 + 256[`
                // `=> [0, 128[`
                //
                // We don't know the radix value, so we have to do the FHE overflowing_sub, but
                // its overflow flag has to be flipped.
                // The exact result is `lhs - s = lhs - (s' - 2ⁿ) = (lhs - s') + 2ⁿ`,
                // i.e the FHE result shifted by a full modulus of the radix.
                //
                // * lhs is in `[-2ⁿ⁻¹, 2ⁿ⁻¹ - 1]`, s' is in `[0, 2ⁿ⁻¹ - 1]`
                // => `lhs - s'` is in `[-2ⁿ + 1, 2ⁿ⁻¹ - 1]` (not considering the modulo)
                // => The subtraction can only "underflow", since only the minimum is below
                //    the radix's minimum (-2ⁿ⁻¹).
                // if lhs - s' is in `[-2ⁿ + 1, -2ⁿ⁻¹ - 1]` then overflow occurred
                // else, lhs - s' is in `[-2ⁿ⁻¹, 2ⁿ⁻¹ - 1]` no overflow occurred
                //
                // adding 2ⁿ to these gives:
                //  `lhs - s' + 2ⁿ` is in
                //  ```
                //      [-2ⁿ + 1 + 2ⁿ, -2ⁿ⁻¹ - 1 + 2ⁿ]
                //  <=> [1, 2ⁿ⁻¹ - 1] This fits the radix range, no overflow
                //  ```
                //  else, lhs - s' + 2ⁿ is in
                //  ```
                //      [-2ⁿ⁻¹ + 2ⁿ, 2ⁿ⁻¹ - 1 + 2ⁿ]
                //  <=> [2ⁿ⁻¹, 2ⁿ⁻¹ - 1 + 2ⁿ] This does not fit the radix range -> overflow
                //  ```
                //
                // So the exact subtraction overflows if and only if the FHE one does not.
                // We have to invert the overflow flag
                //
                // Example:
                //   Radix 2_2, 4 blocks -> signed radix of 8 bits, values in [-128, 127]
                //   And a scalar value `s`: -255i16
                //
                //   s = -255i16 = 0b1111111100000001
                //                           ^- radix sign bit is 0
                //   fhe_overflowing_sub sees s' = 0b00000001 = 1 = s + 256
                //
                //   1) lhs = -128: the FHE computes -128 - 1 = -129 = 127 mod 256 and signals an
                //      overflow. The exact result is -128 + 255 = 127, which fits: the inverted
                //      flag is correct.
                //
                //   2) lhs = 127: the FHE computes 127 - 1 = 126 and signals no overflow. The exact
                //      result is 127 + 255 = 382 = 126 mod 256, which does not fit: the inverted
                //      flag is correct.
                //
                //   In both cases the FHE result is the exact one on 8 bits: only the flag needs
                //   the inversion.
                Self::InvertedFhe
            } else {
                Self::Fhe
            }
        } else {
            let top_bit_not_zero = decomposer.next().is_some_and(|v| {
                let sign_bit = v as u64 / (message_modulus.0 / 2);
                sign_bit != 0
            });
            if decomposer.any(|v| v != 0) {
                Self::TriviallyTrue
            } else if top_bit_not_zero {
                // (With `n` the radix bit width)
                //
                // Same overall idea as for the negative branch above.
                //
                // The clear is positive, bits above the radix width are zeros.
                // However, the bit that is at the position of the radix's sign bit is `1`.
                // This means the clear `s` has a value in range `[2ⁿ⁻¹, 2ⁿ[`
                // or (`[2ⁿ⁻¹, 2ⁿ - 1]`).
                // e.g: signed radix of 8 bits (n=8), clear of 16 bits, under these conditions
                // the clear is in `[128, 256[` (or `[128, 255]`)
                //
                // But since the overflowing_sub done later will only see the truncated version
                // of the clear, it will see a number `s'` in the range `[-2ⁿ⁻¹, -1]`,
                // because the truncated version is seen as a signed clear of n bits, whose
                // sign bit is set, i.e. a negative value.
                // i.e it will see `s' = s - 2ⁿ`
                // e.g taking the example before, the scalar was in `[128, 256[`, the truncated
                // version of the clear given to the FHE op will be interpreted as
                // `[128 - 256, 256 - 256[` <=> `[-128, 0[` <=> `[-128, -1]`
                //
                // We don't know the radix value, so we have to do the FHE overflowing_sub, but
                // its overflow flag has to be flipped.
                // The exact result is `lhs - s = lhs - (s' + 2ⁿ) = (lhs - s') - 2ⁿ`
                // i.e the FHE result shifted ('down') by a full modulus of the radix
                //
                // * lhs is in `[-2ⁿ⁻¹, 2ⁿ⁻¹ - 1]`, s' is in `[-2ⁿ⁻¹, -1]`
                // => `lhs - s'` is in (not considering modulo)
                // ```
                // [-2ⁿ⁻¹ - (-1), 2ⁿ⁻¹ - 1 - (-2ⁿ⁻¹)]
                // [-2ⁿ⁻¹ + 1, 2ⁿ - 1]
                // ```
                //
                // The subtraction can only 'overflow', since only the maximum is above the
                // radix's maximum `2ⁿ⁻¹ - 1`
                //
                // if `lhs - s'` is in `[-2ⁿ⁻¹ + 1, 2ⁿ⁻¹ - 1]` then no overflow occurred
                // else, `lhs - s'` is in `[2ⁿ⁻¹, 2ⁿ - 1]` then overflow occurred
                //
                // subtracting 2ⁿ from these gives:
                // `lhs - s' - 2ⁿ` is in
                //
                // ```
                //     [-2ⁿ⁻¹ + 1 - 2ⁿ, 2ⁿ⁻¹ - 1 - 2ⁿ]
                // <=> [-2ⁿ⁻¹ + 1 - 2ⁿ, -2ⁿ⁻¹ - 1] This does not fit the radix range -> overflow
                // ```
                //
                // else, `lhs - s' - 2ⁿ` is in
                // ```
                //     [2ⁿ⁻¹ - 2ⁿ, 2ⁿ - 1 - 2ⁿ]
                // <=> [-2ⁿ⁻¹, -1] This fits the radix range, no overflow
                // ```
                //
                // So the exact subtraction overflows if and only if the FHE one does not.
                // We have to invert the overflow flag.
                //
                // Example:
                //   Radix 2_2, 4 blocks -> signed radix of 8 bits, values in [-128, 127]
                //   And a scalar value `s`: 255i16
                //
                //   s = 255i16 = 0b0000000011111111
                //                          ^- radix sign bit is 1
                //   fhe_overflowing_sub sees s' = 0b11111111 = -1 = s - 256
                //
                //   1) lhs = 127: the FHE computes 127 - (-1) = 128 = -128 mod 256 and signals an
                //      overflow. The exact result is 127 - 255 = -128, which fits: the inverted
                //      flag is correct.
                //
                //   2) lhs = -128: the FHE computes -128 - (-1) = -127 and signals no overflow. The
                //      exact result is -128 - 255 = -383 = -127 mod 256, which does not fit: the
                //      inverted flag is correct.
                //
                //   In both cases the FHE result is the exact one on 8 bits: only the flag needs
                //   the inversion.
                Self::InvertedFhe
            } else {
                Self::Fhe
            }
        }
    }

    /// Decides how the overflow flag of an overflowing scalar addition between an unsigned
    /// radix of `num_blocks` blocks of `message_modulus` and `scalar` is obtained.
    pub(crate) fn for_unsigned_radix<Scalar>(
        scalar: Scalar,
        num_blocks: usize,
        message_modulus: MessageModulus,
    ) -> Self
    where
        Scalar: DecomposableInto<u8>,
    {
        let mut beyond_radix = BlockDecomposer::new(scalar, message_modulus.0.ilog2())
            .iter_as::<u8>()
            .skip(num_blocks);

        if scalar < Scalar::ZERO {
            // For negative scalar it's slightly more complex:
            //
            // A negative scalar `s` is never in the range of an unsigned radix,
            // but the addition can still produce results valid in the unsigned radix range.
            //
            // With `n` the radix bit width, thus in range `[0, 2ⁿ[`,
            // and `s` the scalar:
            if beyond_radix.any(|v| v != (message_modulus.0 - 1) as u8) {
                // Here `s < -2ⁿ`, so `lhs + s < 0` for every `lhs` and the addition trivially
                // overflows
                Self::TriviallyTrue
            } else {
                // Here `s` is in `[-2ⁿ, 0[` (a scalar narrower than the radix has no block
                // beyond it and always lands here, it is above -2ⁿ by construction).
                // The FHE addition will see the truncated version of `s`, called `s'`
                // that will be interpreted as a positive number in `[0, 2ⁿ[`.
                // I.e: the FHE addition sees `s' = s + 2ⁿ`.
                //
                // The exact result is `lhs + s = (lhs + s') - 2ⁿ`:
                // `lhs + s'` is in `[0, 2ⁿ - 1 + 2ⁿ - 1]` <=> `[0, 2ⁿ⁺¹ - 1[`,
                // so `lhs + s' - 2ⁿ` is in `[-2ⁿ, 2ⁿ - 1[`
                // The addition overflows if `lhs + s` is not in `[0, 2ⁿ[`
                //
                // * When `lhs + s'` is in `[2ⁿ, 2ⁿ⁺¹ - 1[`, then `lhs + s = lhs + s' - 2ⁿ` is in
                //   `[0, 2ⁿ - 1[`
                // i.e, when `lhs + s'` overflows, `lhs + s` does not,
                //
                // * When `lhs + s'` is in `[0, 2ⁿ[`, then `lhs + s = lhs + s' - 2ⁿ` is in `[-2ⁿ,
                //   0[`
                // i.e, when `lhs + s'` does not overflow, `lhs + s` does
                //
                // So the flag computed by the fhe op has to be inverted. The result it
                // computes is correct as is: `lhs + s'` and `lhs + s` differ by `2ⁿ`, the
                // radix modulus, so they are the same value on `n` bits (an example in 2_2
                // with 4 blocks: `5 + (-1)` is computed as `5 + 255 = 260 = 4 mod 256`).
                Self::InvertedFhe
            }
        } else if beyond_radix.any(|v| v != 0) {
            // A positive scalar is either in the range or needs more blocks than the radix,
            // so that case is easily solved
            // (i.e. if its bits above the radix's last bit are non-zero then it is out of range)
            Self::TriviallyTrue
        } else {
            Self::Fhe
        }
    }

    /// Turns the FHE overflow flag, computed when `self` required it, into the final one.
    pub(crate) fn overflow_flag(
        self,
        sks: &ServerKey,
        fhe_flag: Option<BooleanBlock>,
    ) -> BooleanBlock {
        match self {
            Self::TriviallyTrue => sks.create_trivial_boolean_block(true),
            Self::InvertedFhe => {
                let mut flag = fhe_flag.expect("overflow computation was requested");
                sks.boolean_bitnot_assign(&mut flag);
                flag
            }
            Self::Fhe => fhe_flag.expect("overflow computation was requested"),
        }
    }
}

impl ServerKey {
    pub fn overflowing_scalar_add_assign_parallelized<T, Scalar>(
        &self,
        lhs: &mut T,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u8>,
    {
        self.clean_inplace_for_default_op(lhs);

        // Sign extended (or zero extended) to the radix width when the scalar is narrower
        let scalar_blocks = BlockDecomposer::with_block_count(
            scalar,
            self.message_modulus().0.ilog2(),
            lhs.blocks().len(),
        )
        .iter_as::<u8>()
        .collect::<Vec<_>>();

        let flag_source = if T::IS_SIGNED {
            ScalarOverflowFlagSource::for_signed_radix(
                scalar,
                lhs.blocks().len(),
                self.message_modulus(),
            )
        } else {
            ScalarOverflowFlagSource::for_unsigned_radix(
                scalar,
                lhs.blocks().len(),
                self.message_modulus(),
            )
        };

        const INPUT_CARRY: bool = false;
        let maybe_overflow = self.add_assign_scalar_blocks_parallelized(
            lhs,
            scalar_blocks,
            INPUT_CARRY,
            flag_source != ScalarOverflowFlagSource::TriviallyTrue,
        );

        flag_source.overflow_flag(self, maybe_overflow)
    }

    pub fn overflowing_scalar_add_parallelized<T, Scalar>(
        &self,
        lhs: &T,
        scalar: Scalar,
    ) -> (T, BooleanBlock)
    where
        T: IntegerRadixCiphertext,
        Scalar: DecomposableInto<u8>,
    {
        let mut result = lhs.clone();
        let overflowed = self.overflowing_scalar_add_assign_parallelized(&mut result, scalar);
        (result, overflowed)
    }

    pub fn unsigned_overflowing_scalar_add_assign_parallelized<Scalar>(
        &self,
        lhs: &mut RadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8>,
    {
        self.overflowing_scalar_add_assign_parallelized(lhs, scalar)
    }

    pub fn unsigned_overflowing_scalar_add_parallelized<Scalar>(
        &self,
        lhs: &RadixCiphertext,
        scalar: Scalar,
    ) -> (RadixCiphertext, BooleanBlock)
    where
        Scalar: UnsignedNumeric + DecomposableInto<u8>,
    {
        self.overflowing_scalar_add_parallelized(lhs, scalar)
    }

    pub fn signed_overflowing_scalar_add_assign_parallelized<Scalar>(
        &self,
        lhs: &mut SignedRadixCiphertext,
        scalar: Scalar,
    ) -> BooleanBlock
    where
        Scalar: SignedNumeric + DecomposableInto<u8>,
    {
        self.overflowing_scalar_add_assign_parallelized(lhs, scalar)
    }

    pub fn signed_overflowing_scalar_add_parallelized<Scalar>(
        &self,
        lhs: &SignedRadixCiphertext,
        scalar: Scalar,
    ) -> (SignedRadixCiphertext, BooleanBlock)
    where
        Scalar: SignedNumeric + DecomposableInto<u8>,
    {
        self.overflowing_scalar_add_parallelized(lhs, scalar)
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is returned in a new ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 4;
    /// let scalar = 40;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// let ct_res = sks.scalar_add_parallelized(&ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add_parallelized<T, Scalar>(&self, ct: &T, scalar: Scalar) -> T
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        let mut ct_res = ct.clone();
        self.scalar_add_assign_parallelized(&mut ct_res, scalar);
        ct_res
    }

    /// Computes homomorphically the addition of ciphertext with a scalar.
    ///
    /// The result is assigned to the `ct_left` ciphertext.
    ///
    /// This function, like all "default" operations (i.e. not unchecked), will
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
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    ///
    /// // We have 4 * 2 = 8 bits of message
    /// let size = 4;
    /// let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, size);
    ///
    /// let msg = 129;
    /// let scalar = 40;
    ///
    /// let mut ct = cks.encrypt(msg);
    ///
    /// // Compute homomorphically an addition:
    /// sks.scalar_add_assign_parallelized(&mut ct, scalar);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct);
    /// assert_eq!(msg + scalar, dec);
    /// ```
    pub fn scalar_add_assign_parallelized<T, Scalar>(&self, ct: &mut T, scalar: Scalar)
    where
        Scalar: DecomposableInto<u8>,
        T: IntegerRadixCiphertext,
    {
        self.clean_inplace_for_default_op(ct);

        let scalar_blocks = BlockDecomposer::with_block_count(
            scalar,
            self.message_modulus().0.ilog2(),
            ct.blocks().len(),
        )
        .iter_as::<u8>()
        .collect();

        const COMPUTE_OVERFLOW: bool = false;
        const INPUT_CARRY: bool = false;
        self.add_assign_scalar_blocks_parallelized(
            ct,
            scalar_blocks,
            INPUT_CARRY,
            COMPUTE_OVERFLOW,
        );
    }

    pub(crate) fn add_assign_scalar_blocks_parallelized<T>(
        &self,
        lhs: &mut T,
        scalar_blocks: Vec<u8>,
        input_carry: bool,
        compute_overflow: bool,
    ) -> Option<BooleanBlock>
    where
        T: IntegerRadixCiphertext,
    {
        assert_eq!(lhs.blocks().len(), scalar_blocks.len());
        if self.is_eligible_for_parallel_single_carry_propagation(lhs.blocks().len()) {
            self.add_assign_scalar_blocks_with_carry_parallelized(
                lhs,
                scalar_blocks,
                input_carry,
                compute_overflow,
            )
        } else {
            self.add_assign_scalar_blocks_with_carry_sequential(
                lhs,
                scalar_blocks.as_slice(),
                input_carry,
                compute_overflow,
            )
        }
    }

    fn add_assign_scalar_blocks_with_carry_parallelized<T>(
        &self,
        lhs: &mut T,
        mut scalar_blocks: Vec<u8>,
        input_carry: bool,
        compute_overflow: bool,
    ) -> Option<BooleanBlock>
    where
        T: IntegerRadixCiphertext,
    {
        assert!(self.message_modulus().0 >= 4);
        assert!(self.carry_modulus().0 >= self.message_modulus().0);
        assert_eq!(lhs.blocks().len(), scalar_blocks.len());

        if lhs.blocks().is_empty() {
            return if compute_overflow {
                // The ct is empty, so if carry is true, then we consider its an
                // overflow
                Some(self.create_trivial_boolean_block(input_carry))
            } else {
                None
            };
        }

        let packed_modulus = self.message_modulus().0 * self.message_modulus().0;

        let packed_blocks = lhs
            .blocks()
            .chunks(2)
            .map(|chunk| self.pack_block_chunk(chunk))
            .collect::<Vec<_>>();

        // Pack the scalar blocks
        for i in 0..packed_blocks.len() {
            let low = scalar_blocks[i * 2];
            let high = scalar_blocks.get((i * 2) + 1).copied().unwrap_or(0);

            scalar_blocks[i] = (high * self.message_modulus().0 as u8) | low;
        }
        scalar_blocks.truncate(packed_blocks.len());
        let packed_scalar_blocks = scalar_blocks;

        assert_eq!(packed_scalar_blocks.len(), packed_blocks.len());

        let num_blocks = lhs.blocks().len();
        // When the number of blocks is not even, the last packed block's
        // carry will be empty, this is an important detail in a few places
        // (like overflow detection)
        let num_block_is_even = (num_blocks & 1) == 0;

        let mut overflowed = None;
        let (grouping_size, propagation_blocks, shifted_partial_result) = if compute_overflow {
            rayon::join(
                || {
                    self.scalar_compute_shifted_blocks_and_block_states(
                        &packed_blocks,
                        num_block_is_even,
                        packed_modulus,
                        &packed_scalar_blocks,
                        input_carry,
                    )
                },
                || {
                    let last_scalar_block =
                        u64::from(packed_scalar_blocks.last().copied().unwrap());
                    let lut = if T::IS_SIGNED {
                        let num_bits_in_message = if num_block_is_even {
                            packed_modulus.ilog2()
                        } else {
                            self.message_modulus().0.ilog2()
                        };
                        self.key.generate_lookup_table(|last_packed_block| {
                            let mask = (1 << (num_bits_in_message - 1)) - 1;
                            let lhs_except_last_bit = last_packed_block & mask;
                            let rhs_except_last_bit = last_scalar_block & mask;

                            let overflows_with_given_input_carry = |input_carry| {
                                let output_carry =
                                    ((last_packed_block + last_scalar_block + input_carry)
                                        >> num_bits_in_message)
                                        & 1;

                                let input_carry_to_last_bit =
                                    ((lhs_except_last_bit + rhs_except_last_bit + input_carry)
                                        >> (num_bits_in_message - 1))
                                        & 1;

                                u64::from(input_carry_to_last_bit != output_carry)
                            };

                            (overflows_with_given_input_carry(1) << 3)
                                | (overflows_with_given_input_carry(0) << 2)
                        })
                    } else {
                        let modulus = if num_block_is_even {
                            packed_modulus
                        } else {
                            self.message_modulus().0
                        };
                        self.key.generate_lookup_table(|last_packed_block| {
                            let value = last_packed_block + last_scalar_block;
                            if value >= modulus {
                                2 << 1
                            } else if value == modulus - 1 {
                                1 << 1
                            } else {
                                0
                            }
                        })
                    };
                    let last_packed_block = packed_blocks.last().unwrap();
                    overflowed = Some(self.key.apply_lookup_table(last_packed_block, &lut));
                },
            )
            .0
        } else {
            self.scalar_compute_shifted_blocks_and_block_states(
                &packed_blocks,
                num_block_is_even,
                packed_modulus,
                &packed_scalar_blocks,
                input_carry,
            )
        };

        // Second step
        let (mut prepared_blocks, resolved_carries) = {
            let (propagation_simulators, resolved_carries) = self
                .compute_propagation_simulators_and_groups_carries(
                    grouping_size,
                    &propagation_blocks,
                );

            let mut prepared_blocks = shifted_partial_result;
            assert_eq!(
                prepared_blocks.len(),
                (propagation_simulators.len() * 2) - usize::from(!num_block_is_even)
            );
            prepared_blocks
                .chunks_mut(2)
                .zip(propagation_simulators.iter())
                .for_each(|(chunk_of_two, simulator)| {
                    for block in chunk_of_two.iter_mut() {
                        self.key.unchecked_add_assign(block, simulator);
                    }
                });
            assert_eq!(prepared_blocks.len(), num_blocks);

            if let Some(block) = overflowed.as_mut() {
                self.key
                    .unchecked_add_assign(block, propagation_simulators.last().unwrap());
            }

            (prepared_blocks, resolved_carries)
        };

        let extract_message_low_block_mut = self
            .key
            .generate_lookup_table(|block| (block >> 1) % self.message_modulus().0);
        let extract_message_high_block_mut = self
            .key
            .generate_lookup_table(|block| (block >> 2) % self.message_modulus().0);

        assert_eq!(compute_overflow, overflowed.is_some());
        rayon::scope(|s| {
            s.spawn(|_| {
                prepared_blocks
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, block)| {
                        let grouping_index = i / (grouping_size * 2);
                        let carry = &resolved_carries[grouping_index];
                        self.key.unchecked_add_assign(block, carry);

                        let lut = if i % 2 == 0 {
                            &extract_message_low_block_mut
                        } else {
                            &extract_message_high_block_mut
                        };
                        self.key.apply_lookup_table_assign(block, lut);
                    });
            });

            if compute_overflow {
                s.spawn(|_| {
                    let overflowed = overflowed.as_mut().unwrap();
                    self.key
                        .unchecked_add_assign(overflowed, resolved_carries.last().unwrap());

                    let lut = if T::IS_SIGNED {
                        self.key.generate_lookup_table(|block| {
                            let input_carry = (block >> 1) & 1;
                            let does_overflow_if_carry_is_1 = (block >> 3) & 1;
                            let does_overflow_if_carry_is_0 = (block >> 2) & 1;
                            if input_carry == 1 {
                                does_overflow_if_carry_is_1
                            } else {
                                does_overflow_if_carry_is_0
                            }
                        })
                    } else {
                        // In that case the block has been prepared such that after adding the
                        // carry if there is a carry, then the 3nd
                        // bit is set
                        self.key.generate_lookup_table(|block| (block >> 2) & 1)
                    };
                    self.key.apply_lookup_table_assign(overflowed, &lut);
                });
            }
        });

        for (out, b) in lhs.blocks_mut().iter_mut().zip(prepared_blocks.iter_mut()) {
            std::mem::swap(out, b);
        }

        overflowed.map(BooleanBlock::new_unchecked)
    }

    fn scalar_compute_shifted_blocks_and_block_states(
        &self,
        packed_blocks: &[Ciphertext],
        num_block_is_even: bool,
        packed_modulus: u64,
        packed_scalar_blocks: &[u8],
        input_carry: bool,
    ) -> (usize, Vec<Ciphertext>, Vec<Ciphertext>) {
        let num_packing = packed_blocks.len();

        let num_bits_in_block = packed_modulus.ilog2();
        // Just in case we compare with max noise level, but it should always be num_bits_in_blocks
        // with the parameters we provide
        let grouping_size =
            (num_bits_in_block as usize).min(self.key.max_noise_level.get() as usize);

        // In this, we store lookup tables to be used on each 'packing'.
        // These LUTs will generate an output that tells whether the packing
        // generates a carry, propagates, or does nothing
        //
        // The LUT for the first packing is not the same as other packing,
        // consequently LUTs for other packing in the first _grouping_ are
        // not the same as LUTs for other _groupings_.
        let packed_block_state_luts = {
            let mut luts = Vec::with_capacity(grouping_size);
            // We know the first packing is not going to receive any carry
            // so, we use that to our advantage.
            luts.push(self.key.generate_lookup_table(|first_block| {
                let result =
                    first_block + u64::from(packed_scalar_blocks[0]) + u64::from(input_carry);
                if result >= packed_modulus {
                    1 // Generate
                } else {
                    0 // Nothing
                }
            }));

            let generate_block_state_lut =
                |key: &crate::shortint::ServerKey,
                 packed_scalar_block: u64,
                 shift_of_result: usize| {
                    key.generate_lookup_table(|packed_block| {
                        let result = packed_block + packed_scalar_block;
                        let state = if result >= packed_modulus {
                            2 // Generate
                        } else if result == packed_modulus - 1 {
                            1 // Propagate
                        } else {
                            0 // Nothing
                        };

                        state << shift_of_result
                    })
                };

            // LUTs for other packing in the _first grouping_
            for (index_in_grouping, packed_scalar_block) in packed_scalar_blocks
                .get(1..grouping_size.min(packed_scalar_blocks.len()))
                .unwrap_or(&[])
                .iter()
                .copied()
                .enumerate()
            {
                luts.push(generate_block_state_lut(
                    &self.key,
                    u64::from(packed_scalar_block),
                    index_in_grouping,
                ));
            }

            // LUTs for the rest of the groupings
            //
            // The difference with the loop above is that the index_in_grouping
            // starts at 0 for the first block of each group, whereas for the first
            // group (loop above), the index_in_grouping started as 0 for the second block
            for (i, packed_scalar_block) in packed_scalar_blocks
                .get(grouping_size..)
                .unwrap_or(&[])
                .iter()
                .copied()
                .enumerate()
            {
                let index_in_grouping = i % grouping_size;
                luts.push(generate_block_state_lut(
                    &self.key,
                    u64::from(packed_scalar_block),
                    index_in_grouping,
                ));
            }

            assert_eq!(luts.len(), packed_blocks.len());

            luts
        };

        // In this we store lookup tables that prepare the `low` and `high` block from a
        // _packing_ to be in a state were they are ready to receive `propagation simulator`
        // for previous packing in the same grouping they belong.
        let block_preparator_luts = {
            let mut luts = Vec::with_capacity(packed_blocks.len());
            for (i, packed_scalar_block) in packed_scalar_blocks.iter().copied().enumerate() {
                let packed_scalar_block = u64::from(packed_scalar_block);

                // LUT to prepare the low block
                luts.push(self.key.generate_lookup_table(|packed_block| {
                    let carry = if i == 0 { u64::from(input_carry) } else { 0 };
                    let result =
                        (packed_block + packed_scalar_block + carry) % self.message_modulus().0;

                    // Shift by one as this will receive the carry of the group directly
                    result << 1
                }));

                if i == num_packing - 1 && !num_block_is_even {
                    // The number of non-packed block is odd, so last packing does not have
                    // a high block
                    continue;
                }

                // LUT to prepare the high block
                luts.push(self.key.generate_lookup_table(|packed_block| {
                    let high_block = packed_block / self.message_modulus().0;
                    let high_scalar_block = packed_scalar_block / self.message_modulus().0;
                    let low_block = packed_block % self.message_modulus().0;
                    let low_scalar_block = packed_scalar_block % self.message_modulus().0;
                    let carry = if i == 0 { u64::from(input_carry) } else { 0 };

                    let low_block_result = low_block + low_scalar_block + carry;

                    let low_block_state = if low_block_result >= self.message_modulus().0 {
                        2 // Generate
                    } else if low_block_result == (self.message_modulus().0 - 1) {
                        1 // Propagate
                    } else {
                        0 // Neither
                    };

                    let mut high_block_result =
                        (high_block + high_scalar_block) % self.message_modulus().0;
                    high_block_result <<= 2;

                    (high_block_result + (low_block_state << 1)) % packed_modulus
                }));
            }

            assert_eq!(
                luts.len(),
                (packed_blocks.len() * 2) - usize::from(!num_block_is_even)
            );

            luts
        };

        let (propagation_blocks, shifted_partial_result) = rayon::join(
            || {
                // we dont care about last block carry
                packed_blocks[0..packed_blocks.len() - 1]
                    .par_iter()
                    .zip(packed_block_state_luts.par_iter())
                    .map(|(packed_block, lut)| self.key.apply_lookup_table(packed_block, lut))
                    .collect::<Vec<_>>()
            },
            || {
                let mut blocks = Vec::with_capacity(packed_blocks.len() * 2);
                for block in packed_blocks[..packed_blocks.len().saturating_sub(1)].iter() {
                    blocks.push(block.clone());
                    blocks.push(block.clone());
                }
                if let Some(last_packing) = packed_blocks.last() {
                    blocks.push(last_packing.clone());
                    if num_block_is_even {
                        // The number of non-packed block is even, so each packing
                        // as low and high block
                        blocks.push(last_packing.clone());
                    }
                }

                assert_eq!(blocks.len(), block_preparator_luts.len());

                blocks
                    .par_iter_mut()
                    .zip(block_preparator_luts.par_iter())
                    .for_each(|(block, lut)| {
                        self.key.apply_lookup_table_assign(block, lut);
                    });
                blocks
            },
        );
        (grouping_size, propagation_blocks, shifted_partial_result)
    }

    fn add_assign_scalar_blocks_with_carry_sequential<T>(
        &self,
        lhs: &mut T,
        scalar_blocks: &[u8],
        input_carry: bool,
        compute_overflow: bool,
    ) -> Option<BooleanBlock>
    where
        T: IntegerRadixCiphertext,
    {
        assert!(!lhs.blocks().is_empty());
        assert_eq!(lhs.blocks().len(), scalar_blocks.len());

        let num_blocks = lhs.blocks().len();

        let mut carry = self.key.create_trivial(u64::from(input_carry));
        // Process all blocks but the last one
        // as we will do overflow computation when processing the last block
        for (lhs_b, scalar_b) in lhs.blocks_mut()[..num_blocks - 1]
            .iter_mut()
            .zip(scalar_blocks.iter().copied())
        {
            self.key.unchecked_scalar_add_assign(lhs_b, scalar_b);
            self.key.unchecked_add_assign(lhs_b, &carry);

            carry.clone_from(lhs_b);

            rayon::join(
                || {
                    self.key.message_extract_assign(lhs_b);
                },
                || {
                    self.key.carry_extract_assign(&mut carry);
                },
            );
        }

        let last_block = lhs.blocks_mut().last_mut().unwrap();
        let mut saved_last_block = last_block.clone();
        let last_scalar_b = scalar_blocks.last().copied().unwrap();
        self.key
            .unchecked_scalar_add_assign(last_block, last_scalar_b);
        self.key.unchecked_add_assign(last_block, &carry);

        rayon::scope(|s| {
            s.spawn(|_| {
                self.key.message_extract_assign(last_block);
            });

            if compute_overflow {
                s.spawn(|_| {
                    let last_scalar_b = u64::from(last_scalar_b);
                    let lut = self.key.generate_lookup_table_bivariate(
                        |last_block, input_carry_into_last_block| {
                            let output_carry =
                                (last_block + last_scalar_b + input_carry_into_last_block)
                                    / self.message_modulus().0;

                            if T::IS_SIGNED {
                                let input_carry_to_last_bit = if self.message_modulus().0 > 2 {
                                    // i.e divided by 2
                                    let modulus_without_last_bit = self.message_modulus().0 >> 1;
                                    let mask_to_remove_last_bit = modulus_without_last_bit - 1;

                                    let last_block_except_last_bit =
                                        last_block & mask_to_remove_last_bit;
                                    let last_scalar_expect_last_bit =
                                        last_scalar_b & mask_to_remove_last_bit;

                                    (last_scalar_expect_last_bit
                                        + last_block_except_last_bit
                                        + input_carry_into_last_block)
                                        / modulus_without_last_bit
                                } else {
                                    // blocks store only one bit of message
                                    // so the input carry of the block is the input carry
                                    // of the last bit
                                    input_carry_into_last_block
                                };

                                u64::from(input_carry_to_last_bit != output_carry)
                            } else {
                                // mask by one just so the degree estimation correctly says
                                // Degree 1 as the out degree for this LUT
                                output_carry & 1
                            }
                        },
                    );
                    self.key.unchecked_apply_lookup_table_bivariate_assign(
                        &mut saved_last_block,
                        &carry,
                        &lut,
                    );
                });
            }
        });

        if compute_overflow {
            Some(BooleanBlock::new_unchecked(saved_last_block))
        } else {
            None
        }
    }
}
