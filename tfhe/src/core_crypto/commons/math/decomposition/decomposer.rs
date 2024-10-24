use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecompositionIter, SignedDecompositionNonNativeIter, SliceSignedDecompositionIter,
    SliceSignedDecompositionNonNativeIter, ValueSign,
};
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use std::marker::PhantomData;

/// A structure which allows to decompose unsigned integers into a set of smaller terms.
///
/// See the [module level](super) documentation for a description of the signed decomposition.
#[derive(Debug)]
pub struct SignedDecomposer<Scalar>
where
    Scalar: UnsignedInteger,
{
    pub(crate) base_log: usize,
    pub(crate) level_count: usize,
    integer_type: PhantomData<Scalar>,
}

#[inline(always)]
pub fn native_closest_representable<Scalar: UnsignedInteger>(
    input: Scalar,
    level_count: usize,
    base_log: usize,
) -> Scalar {
    // The closest number representable by the decomposition can be computed by performing
    // the rounding at the appropriate bit.

    // We compute the number of least significant bits which can not be represented by the
    // decomposition
    // Example with level_count = 3, base_log = 4 and BITS == 64 -> 52
    let non_rep_bit_count: usize = Scalar::BITS - level_count * base_log;
    let shift = non_rep_bit_count - 1;
    // Move the representable bits + 1 to the LSB, with our example :
    //       |-----| 64 - (64 - 12 - 1) == 13 bits
    // 0....0XX...XX
    let mut res = input >> shift;
    // Add one to do the rounding by adding the half interval
    res += Scalar::ONE;
    // Discard the LSB which was the one deciding in which direction we round
    // -2 == 111...1110, i.e. all bits are 1 except the LSB which is 0 allowing to zero it
    res &= Scalar::TWO.wrapping_neg();
    // Shift back to the right position
    res << shift
}

impl<Scalar> SignedDecomposer<Scalar>
where
    Scalar: UnsignedInteger,
{
    /// Create a new decomposer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// assert_eq!(decomposer.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(decomposer.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn new(base_log: DecompositionBaseLog, level_count: DecompositionLevelCount) -> Self {
        debug_assert!(
            Scalar::BITS > base_log.0 * level_count.0,
            "Decomposed bits exceeds the size of the integer to be decomposed"
        );
        Self {
            base_log: base_log.0,
            level_count: level_count.0,
            integer_type: PhantomData,
        }
    }

    /// Return the logarithm in base two of the base of this decomposer.
    ///
    /// If the decomposer uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// assert_eq!(decomposer.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Return the number of levels of this decomposer.
    ///
    /// If the decomposer uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// assert_eq!(decomposer.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }

    /// Return the closet value representable by the decomposition.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let closest = decomposer.closest_representable(1_340_987_234_u32);
    /// assert_eq!(closest, 1_341_128_704_u32);
    /// ```
    #[inline]
    pub fn closest_representable(&self, input: Scalar) -> Scalar {
        native_closest_representable(input, self.level_count, self.base_log)
    }

    /// Decode a plaintext value using the decoder to compute the closest representable.
    pub fn decode_plaintext(&self, input: Scalar) -> Scalar {
        let shift = Scalar::BITS - self.level_count * self.base_log;
        self.closest_representable(input) >> shift
    }

    /// Fills a mutable tensor-like objects with the closest representable values from another
    /// tensor-like object.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    ///
    /// let input = vec![1_340_987_234_u32; 2];
    /// let mut closest = vec![0u32; 2];
    /// decomposer.fill_slice_with_closest_representable(&mut closest, &input);
    /// assert!(closest.iter().all(|&x| x == 1_341_128_704_u32));
    /// ```
    pub fn fill_slice_with_closest_representable(&self, output: &mut [Scalar], input: &[Scalar]) {
        assert_eq!(output.len(), input.len());
        output
            .iter_mut()
            .zip(input.iter())
            .for_each(|(dst, &src)| *dst = self.closest_representable(src));
    }

    /// Generate an iterator over the terms of the decomposition of the input.
    ///
    /// # Warning
    ///
    /// The returned iterator yields the terms $\tilde{\theta}\_i$ in order of decreasing $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::numeric::UnsignedInteger;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// // 2147483647 == 2^31 - 1 and has a decomposition term == to half_basis
    /// for term in decomposer.decompose(2147483647u32) {
    ///     assert!(1 <= term.level().0);
    ///     assert!(term.level().0 <= 3);
    ///     let signed_term = term.value().into_signed();
    ///     let half_basis = 2i32.pow(4) / 2i32;
    ///     assert!(
    ///         -half_basis <= signed_term,
    ///         "{} <= {signed_term} failed",
    ///         -half_basis
    ///     );
    ///     assert!(
    ///         signed_term <= half_basis,
    ///         "{signed_term} <= {half_basis} failed"
    ///     );
    /// }
    /// assert_eq!(decomposer.decompose(1).count(), 3);
    /// ```
    pub fn decompose(&self, input: Scalar) -> SignedDecompositionIter<Scalar> {
        // Note that there would be no sense of making the decomposition on an input which was
        // not rounded to the closest representable first. We then perform it before decomposing.
        SignedDecompositionIter::new(
            self.closest_representable(input),
            DecompositionBaseLog(self.base_log),
            DecompositionLevelCount(self.level_count),
        )
    }

    /// Recomposes a decomposed value by summing all the terms.
    ///
    /// If the input iterator yields $\tilde{\theta}\_i$, this returns
    /// $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let val = 1_340_987_234_u32;
    /// let dec = decomposer.decompose(val);
    /// let rec = decomposer.recompose(dec);
    /// assert_eq!(decomposer.closest_representable(val), rec.unwrap());
    /// ```
    pub fn recompose(&self, decomp: SignedDecompositionIter<Scalar>) -> Option<Scalar> {
        if decomp.is_fresh() {
            Some(decomp.fold(Scalar::ZERO, |acc, term| {
                acc.wrapping_add(term.to_recomposition_summand())
            }))
        } else {
            None
        }
    }

    /// Generates an iterator-like object over tensors of terms of the decomposition of the input
    /// tensor.
    ///
    /// # Warning
    ///
    /// The returned iterator yields the terms $(\tilde{\theta}^{(a)}\_i)\_{a\in\mathbb{N}}$ in
    /// order of decreasing $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::numeric::UnsignedInteger;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let decomposable = vec![1_340_987_234_u32, 1_340_987_234_u32];
    /// let mut decomp = decomposer.decompose_slice(&decomposable);
    ///
    /// let mut count = 0;
    /// while let Some(term) = decomp.next_term() {
    ///     assert!(1 <= term.level().0);
    ///     assert!(term.level().0 <= 3);
    ///     for elmt in term.as_slice().iter() {
    ///         let signed_term = elmt.into_signed();
    ///         let half_basis = 2i32.pow(4) / 2i32;
    ///         assert!(-half_basis <= signed_term);
    ///         assert!(signed_term < half_basis);
    ///     }
    ///     count += 1;
    /// }
    /// assert_eq!(count, 3);
    /// ```
    pub fn decompose_slice(&self, input: &[Scalar]) -> SliceSignedDecompositionIter<Scalar> {
        // Note that there would be no sense of making the decomposition on an input which was
        // not rounded to the closest representable first. We then perform it before decomposing.
        let mut closest = vec![Scalar::ZERO; input.len()];
        self.fill_slice_with_closest_representable(&mut closest, input);
        SliceSignedDecompositionIter::new(
            &closest,
            DecompositionBaseLog(self.base_log),
            DecompositionLevelCount(self.level_count),
        )
    }

    /// Fills the output tensor with the recomposition of another tensor.
    ///
    /// Returns `Some(())` if the decomposition was fresh, and the output was filled with a
    /// recomposition, and `None`, if not.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let mut rounded = vec![0u32; 2];
    /// decomposer.fill_slice_with_closest_representable(&mut rounded, &decomposable);
    /// let decomp = decomposer.decompose_slice(&rounded);
    /// let mut recomposition = vec![0u32; 2];
    /// decomposer
    ///     .fill_slice_with_recompose(decomp, &mut recomposition)
    ///     .unwrap();
    /// assert_eq!(recomposition, rounded);
    /// ```
    pub fn fill_slice_with_recompose(
        &self,
        decomp: SliceSignedDecompositionIter<Scalar>,
        output: &mut [Scalar],
    ) -> Option<()> {
        let mut decomp = decomp;
        if decomp.is_fresh() {
            while let Some(term) = decomp.next_term() {
                term.update_slice_with_recomposition_summand_wrapping_addition(output);
            }
            Some(())
        } else {
            None
        }
    }
}

/// A structure which allows to decompose unsigned integers into a set of smaller terms for moduli
/// which are non power of 2.
///
/// See the [module level](super) documentation for a description of the signed decomposition.
#[derive(Debug)]
pub struct SignedDecomposerNonNative<Scalar>
where
    Scalar: UnsignedInteger,
{
    pub(crate) base_log: usize,
    pub(crate) level_count: usize,
    pub(crate) ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar> SignedDecomposerNonNative<Scalar>
where
    Scalar: UnsignedInteger,
{
    /// Create a new decomposer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// assert_eq!(decomposer.level_count(), DecompositionLevelCount(3));
    /// assert_eq!(decomposer.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn new(
        base_log: DecompositionBaseLog,
        level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            !ciphertext_modulus.is_power_of_two(),
            "Got a power of 2 modulus as input for SignedDecomposerNonNative, \
            this is not supported, use SignedDecomposer instead"
        );

        let sself = Self {
            base_log: base_log.0,
            level_count: level_count.0,
            ciphertext_modulus,
        };

        let log2_containing_modulus = sself.ciphertext_modulus_bit_count();

        debug_assert!(
            log2_containing_modulus > (base_log.0 * level_count.0) as u32,
            "Decomposed bits exceeds the size of the integer modulus"
        );

        sself
    }

    /// Return the logarithm in base two of the base of this decomposer.
    ///
    /// If the decomposer uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// assert_eq!(decomposer.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Return the number of levels of this decomposer.
    ///
    /// If the decomposer uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// assert_eq!(decomposer.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }

    /// Return the ciphertext modulus of this decomposer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// assert_eq!(
    ///     decomposer.ciphertext_modulus(),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap()
    /// );
    /// ```
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    /// Returns the number of bits of the ciphertext modulus used to construct the
    /// [`SignedDecomposerNonNative`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 52) + 1).unwrap(),
    /// );
    /// assert_eq!(decomposer.ciphertext_modulus_bit_count(), 53);
    /// ```
    pub fn ciphertext_modulus_bit_count(&self) -> u32 {
        self.ciphertext_modulus.get_custom_modulus().ceil_ilog2()
    }

    /// Return the closet value representable by the decomposition.
    ///
    /// For some input integer `k`, decomposition base `B`, decomposition level count `l` and given
    /// ciphertext modulus `q` the performed operation is the following:
    ///
    /// $$
    /// \lfloor \frac{k\cdot q}{B^{l}} \rceil \cdot B^{l}
    /// $$
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 48) - 1).unwrap(),
    /// );
    /// let (closest_abs, sign) = decomposer.init_decomposer_state(249280154129830u64);
    /// assert_eq!(closest_abs, 32160715112448u64);
    ///
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 48) + 1).unwrap(),
    /// );
    /// let (closest_abs, sign) = decomposer.init_decomposer_state(249280154129830u64);
    /// assert_eq!(closest_abs, 32160715112448u64);
    /// ```
    #[inline]
    pub fn closest_representable(&self, input: Scalar) -> Scalar {
        let (abs_closest, sign) = self.init_decomposer_state(input);

        let modulus_as_scalar: Scalar = self.ciphertext_modulus.get_custom_modulus().cast_into();
        match sign {
            ValueSign::Positive => abs_closest,
            ValueSign::Negative => abs_closest.wrapping_neg_custom_mod(modulus_as_scalar),
        }
    }

    /// Decode a plaintext value using the decoder modulo a custom modulus.
    pub fn decode_plaintext(&self, input: Scalar) -> Scalar {
        let ciphertext_modulus_as_scalar: Scalar =
            self.ciphertext_modulus.get_custom_modulus().cast_into();
        let mut negate_input = false;
        let mut ptxt = input;
        if input > ciphertext_modulus_as_scalar >> 1 {
            negate_input = true;
            ptxt = ptxt.wrapping_neg_custom_mod(ciphertext_modulus_as_scalar);
        }
        let number_of_message_bits = self.base_log().0 * self.level_count().0;
        let delta = ciphertext_modulus_as_scalar >> number_of_message_bits;
        let half_delta = delta >> 1;
        let mut decoded = (ptxt + half_delta) / delta;
        if negate_input {
            decoded = decoded.wrapping_neg_custom_mod(ciphertext_modulus_as_scalar);
        }
        decoded
    }

    #[inline(always)]
    pub fn init_decomposer_state(&self, input: Scalar) -> (Scalar, ValueSign) {
        let ciphertext_modulus_as_scalar: Scalar =
            self.ciphertext_modulus.get_custom_modulus().cast_into();

        // Positive in the modular sense, when seeing the modulo operation as operating on
        // [-q/2; q/2[ and mapping [q/2; q[ to [-q/2; 0[
        // We want to check input < q / 2
        // for q even the division is exact so no problem
        // for q odd, e.g. q = 9 we want input < 4.5
        // as input is an integer we can round q / 2 = 4.5 up to 5
        // then input € [0; 4] will correctly register as < ceil(q / 2)
        let (abs_value, input_sign) = if input < ciphertext_modulus_as_scalar.div_ceil(Scalar::TWO)
        {
            (input, ValueSign::Positive)
        } else {
            (ciphertext_modulus_as_scalar - input, ValueSign::Negative)
        };

        let abs_closest_representable = {
            let shift_to_native = Scalar::BITS - self.ciphertext_modulus_bit_count() as usize;
            native_closest_representable(
                abs_value << shift_to_native,
                self.level_count,
                self.base_log,
            ) >> shift_to_native
        };

        (abs_closest_representable, input_sign)
    }

    pub fn init_decomposer_state_slice(
        &self,
        input: &[Scalar],
        output: &mut [Scalar],
        signs: &mut [ValueSign],
    ) {
        assert_eq!(input.len(), output.len());
        assert_eq!(input.len(), signs.len());
        let ciphertext_modulus_as_scalar: Scalar =
            self.ciphertext_modulus.get_custom_modulus().cast_into();
        let shift_to_native = Scalar::BITS - self.ciphertext_modulus_bit_count() as usize;

        input
            .iter()
            .zip(output.iter_mut())
            .zip(signs.iter_mut())
            .for_each(|((input, output), sign)| {
                if *input < ciphertext_modulus_as_scalar.div_ceil(Scalar::TWO) {
                    (*output, *sign) = (*input, ValueSign::Positive)
                } else {
                    (*output, *sign) = (ciphertext_modulus_as_scalar - *input, ValueSign::Negative)
                };
                *output = native_closest_representable(
                    *output << shift_to_native,
                    self.level_count,
                    self.base_log,
                ) >> shift_to_native
            });
    }

    /// Generate an iterator over the terms of the decomposition of the input.
    ///
    /// # Warning
    ///
    /// The returned iterator yields the terms $\tilde{\theta}\_i$ in order of decreasing $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::numeric::UnsignedInteger;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    ///
    /// let decomposition_base_log = DecompositionBaseLog(4);
    /// let decomposition_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
    ///
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// let basis = 2i64.pow(decomposition_base_log.0.try_into().unwrap());
    /// let half_basis = basis / 2;
    ///
    /// // These two values allow to take each arm of the half basis check below
    /// // 9223372032559808513 == 2^63 - 2^32 + 1 and has a decomposition term == to half_basis
    /// for value in [1u64 << 63, 9223372032559808513u64] {
    ///     for term in decomposer.decompose(value) {
    ///         assert!(1 <= term.level().0);
    ///         assert!(term.level().0 <= 3);
    ///         let signed_term = term.value().into_signed();
    ///         assert!(
    ///             -half_basis <= signed_term,
    ///             "{} <= {signed_term} failed",
    ///             -half_basis
    ///         );
    ///         assert!(
    ///             signed_term <= half_basis,
    ///             "{signed_term} <= {half_basis} failed"
    ///         );
    ///     }
    ///     assert_eq!(decomposer.decompose(1).count(), 3);
    /// }
    /// ```
    pub fn decompose(&self, input: Scalar) -> SignedDecompositionNonNativeIter<Scalar> {
        let (abs_closest_representable, input_sign) = self.init_decomposer_state(input);

        SignedDecompositionNonNativeIter::new(
            abs_closest_representable,
            input_sign,
            DecompositionBaseLog(self.base_log),
            DecompositionLevelCount(self.level_count),
            self.ciphertext_modulus,
        )
    }

    /// Recomposes a decomposed value by summing all the terms.
    ///
    /// If the input iterator yields $\tilde{\theta}\_i$, this returns
    /// $\sum\_{i=1}^l\tilde{\theta}\_i\frac{v}{B^i}$ where $\lambda = \lceil{\log_2{q}}\rceil$ and
    /// $ v = 2^{\lambda} $.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u64>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let val = (1u64 << 63) + (1_340_987_234_u64 << 32);
    /// let dec = decomposer.decompose(val);
    /// let rec = decomposer.recompose(dec);
    /// assert_eq!(decomposer.closest_representable(val), rec.unwrap());
    /// ```
    pub fn recompose(&self, decomp: SignedDecompositionNonNativeIter<Scalar>) -> Option<Scalar> {
        let ciphertext_modulus_as_scalar: Scalar =
            self.ciphertext_modulus().get_custom_modulus().cast_into();
        if decomp.is_fresh() {
            Some(decomp.fold(Scalar::ZERO, |acc, term| {
                acc.wrapping_add_custom_mod(
                    term.to_approximate_recomposition_summand(),
                    ciphertext_modulus_as_scalar,
                )
            }))
        } else {
            None
        }
    }

    /// Fills a mutable tensor-like objects with the closest representable values from another
    /// tensor-like object.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{SignedDecomposerNonNative, ValueSign};
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 48) + 1).unwrap(),
    /// );
    ///
    /// let input = vec![249280154129830u64; 2];
    /// let mut closest = vec![0u64; 2];
    /// let mut signs = vec![ValueSign::Positive; 2];
    /// decomposer.init_decomposer_state_slice(&input, &mut closest, &mut signs);
    /// assert!(closest.iter().all(|&x| x == 32160715112448u64));
    /// decomposer.fill_slice_with_closest_representable(&mut closest, &input);
    /// assert!(closest.iter().all(|&x| x == 249314261598209u64));
    /// ```
    pub fn fill_slice_with_closest_representable(&self, output: &mut [Scalar], input: &[Scalar]) {
        assert_eq!(output.len(), input.len());
        let mut signs = vec![ValueSign::Positive; input.len()];
        self.init_decomposer_state_slice(input, output, &mut signs);

        let modulus_as_scalar: Scalar = self.ciphertext_modulus.get_custom_modulus().cast_into();
        output
            .iter_mut()
            .zip(signs.iter())
            .for_each(|(output, sign)| match sign {
                ValueSign::Positive => (),
                ValueSign::Negative => *output = output.wrapping_neg_custom_mod(modulus_as_scalar),
            });
    }

    /// Generates an iterator-like object over tensors of terms of the decomposition of the input
    /// tensor.
    ///
    /// # Warning
    ///
    /// The returned iterator yields the terms $(\tilde{\theta}^{(a)}\_i)\_{a\in\mathbb{N}}$ in
    /// order of decreasing $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::numeric::UnsignedInteger;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    ///
    /// let decomposition_base_log = DecompositionBaseLog(4);
    /// let decomposition_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
    ///
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     decomposition_base_log,
    ///     decomposition_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// let basis = 2i64.pow(decomposition_base_log.0.try_into().unwrap());
    /// let half_basis = basis / 2;
    ///
    /// let decomposable = [9223372032559808513u64, 1u64 << 63];
    /// let mut decomp = decomposer.decompose_slice(&decomposable);
    ///
    /// let mut count = 0;
    /// while let Some(term) = decomp.next_term() {
    ///     assert!(1 <= term.level().0);
    ///     assert!(term.level().0 <= 3);
    ///     for elmt in term.as_slice().iter() {
    ///         let signed_term = elmt.into_signed();
    ///         assert!(-half_basis <= signed_term);
    ///         assert!(signed_term <= half_basis);
    ///     }
    ///     count += 1;
    /// }
    /// assert_eq!(count, 3);
    /// ```
    pub fn decompose_slice(
        &self,
        input: &[Scalar],
    ) -> SliceSignedDecompositionNonNativeIter<Scalar> {
        let mut abs_closest_representables = vec![Scalar::ZERO; input.len()];
        let mut signs = vec![ValueSign::Positive; input.len()];
        self.init_decomposer_state_slice(input, &mut abs_closest_representables, &mut signs);

        SliceSignedDecompositionNonNativeIter::new(
            &abs_closest_representables,
            &signs,
            DecompositionBaseLog(self.base_log),
            DecompositionLevelCount(self.level_count),
            self.ciphertext_modulus,
        )
    }

    /// Fills the output tensor with the recomposition of another tensor.
    ///
    /// Returns `Some(())` if the decomposition was fresh, and the output was filled with a
    /// recomposition, and `None`, if not.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    ///
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 32) - (1 << 16) + 1).unwrap();
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     ciphertext_modulus,
    /// );
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let mut rounded = vec![0u32; 2];
    /// decomposer.fill_slice_with_closest_representable(&mut rounded, &decomposable);
    /// let decomp = decomposer.decompose_slice(&rounded);
    /// let mut recomposition = vec![0u32; 2];
    /// decomposer
    ///     .fill_slice_with_recompose(decomp, &mut recomposition)
    ///     .unwrap();
    /// assert_eq!(recomposition, rounded);
    /// ```
    pub fn fill_slice_with_recompose(
        &self,
        decomp: SliceSignedDecompositionNonNativeIter<Scalar>,
        output: &mut [Scalar],
    ) -> Option<()> {
        let mut decomp = decomp;
        if decomp.is_fresh() {
            while let Some(term) = decomp.next_term() {
                term.update_slice_with_recomposition_summand_wrapping_addition(output);
            }
            Some(())
        } else {
            None
        }
    }
}
