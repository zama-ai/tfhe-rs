use crate::core_crypto::algorithms::divide_round;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecompositionIter, SignedDecompositionIterNonNative,
};
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
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
    pub fn new(
        base_log: DecompositionBaseLog,
        level_count: DecompositionLevelCount,
    ) -> SignedDecomposer<Scalar> {
        debug_assert!(
            Scalar::BITS > base_log.0 * level_count.0,
            "Decomposed bits exceeds the size of the integer to be decomposed"
        );
        SignedDecomposer {
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
        // The closest number representable by the decomposition can be computed by performing
        // the rounding at the appropriate bit.

        // We compute the number of least significant bits which can not be represented by the
        // decomposition
        let non_rep_bit_count: usize = <Scalar as Numeric>::BITS - self.level_count * self.base_log;
        // We generate a mask which captures the non representable bits
        let non_rep_mask = Scalar::ONE << (non_rep_bit_count - 1);
        // We retrieve the non representable bits
        let non_rep_bits = input & non_rep_mask;
        // We extract the msb of the  non representable bits to perform the rounding
        let non_rep_msb = non_rep_bits >> (non_rep_bit_count - 1);
        // We remove the non-representable bits and perform the rounding
        let res = input >> non_rep_bit_count;
        let res = res + non_rep_msb;
        res << non_rep_bit_count
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
    /// for term in decomposer.decompose(1_340_987_234_u32) {
    ///     assert!(1 <= term.level().0);
    ///     assert!(term.level().0 <= 3);
    ///     let signed_term = term.value().into_signed();
    ///     let half_basis = 2i32.pow(4) / 2i32;
    ///     assert!(-half_basis <= signed_term);
    ///     assert!(signed_term < half_basis);
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
    ) -> SignedDecomposerNonNative<Scalar> {
        debug_assert!(
            Scalar::BITS > base_log.0 * level_count.0,
            "Decomposed bits exceeds the size of the integer to be decomposed"
        );
        SignedDecomposerNonNative {
            base_log: base_log.0,
            level_count: level_count.0,
            ciphertext_modulus,
        }
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
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let closest = decomposer.closest_representable(16982820785129133100u64);
    /// assert_eq!(closest, 16983074190859960321u64);
    /// ```
    #[inline]
    pub fn closest_representable(&self, input: Scalar) -> Scalar {
        let (interval_count, shift) = self.init_decomposition_state(input);
        let ciphertext_modulus = self.ciphertext_modulus.get_custom_modulus();
        let base = Scalar::ONE << self.base_log;
        if base == shift {
            let interval_count: u128 = interval_count.cast_into();
            let base_to_the_level = 1u128 << (self.base_log * self.level_count);
            Scalar::cast_from(
                divide_round(interval_count * ciphertext_modulus, base_to_the_level)
                    % ciphertext_modulus,
            )
        } else {
            let interval_count: u128 = interval_count.cast_into();
            let base_to_the_level = 1u128 << (self.base_log * self.level_count);
            let mod_over_bl = divide_round(ciphertext_modulus, base_to_the_level);
            Scalar::cast_from(interval_count * mod_over_bl)
        }
    }

    #[inline]
    pub fn init_decomposition_state(&self, input: Scalar) -> (Scalar, Scalar) {
        // TODO: Some of these can be precomputed to chose one state init over the other
        let ciphertext_modulus = self.ciphertext_modulus.get_custom_modulus();
        let base = 1u128 << self.base_log;
        let base_to_the_level = 1u128 << (self.base_log * self.level_count);
        let mod_over_base = divide_round(ciphertext_modulus, base);
        let shift = divide_round(ciphertext_modulus, mod_over_base);
        let input_u128: u128 = input.cast_into();

        if shift == base {
            let mul_u128 = input_u128 * base_to_the_level;
            let rounded_u128 = divide_round(mul_u128, ciphertext_modulus);
            (Scalar::cast_from(rounded_u128), Scalar::cast_from(shift))
        } else {
            let mod_over_bl = divide_round(ciphertext_modulus, base_to_the_level);
            let rounded_u128 = divide_round(input_u128, mod_over_bl);
            (Scalar::cast_from(rounded_u128), Scalar::cast_from(shift))
        }
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
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    ///
    /// // These two values allow to take each arm of the half basis check below
    /// for value in [1u64 << 63, 16982820785129133100u64] {
    ///     for term in decomposer.decompose(value) {
    ///         assert!(1 <= term.level().0);
    ///         assert!(term.level().0 <= 3);
    ///         let term = term.value();
    ///         let abs_term = if term < decomposer.ciphertext_modulus().get_custom_modulus() as u64 / 2
    ///         {
    ///             term
    ///         } else {
    ///             decomposer.ciphertext_modulus().get_custom_modulus() as u64 - term
    ///         };
    ///         println!("abs_term: {abs_term}");
    ///         let half_basis = 2u64.pow(4) / 2u64;
    ///         println!("half_basis: {half_basis}");
    ///         assert!(abs_term <= half_basis);
    ///     }
    ///     assert_eq!(decomposer.decompose(1).count(), 3);
    /// }
    /// ```
    pub fn decompose(&self, input: Scalar) -> SignedDecompositionIterNonNative<Scalar> {
        // Note that there would be no sense of making the decomposition on an input which was
        // not rounded to the closest representable first. We then perform it before decomposing.
        SignedDecompositionIterNonNative::new(
            self.init_decomposition_state(input),
            DecompositionBaseLog(self.base_log),
            DecompositionLevelCount(self.level_count),
            self.ciphertext_modulus,
        )
    }

    /// Recomposes a decomposed value by summing all the terms.
    ///
    /// If the input iterator yields $\tilde{\theta}\_i$, this returns
    /// $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$.
    ///
    /// # Warning
    /// Note: all recompositions may not be exact if $B^i$ for all $i <= l$ does not divide $q$.
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
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let val = 1u64 << 60;
    /// let dec = decomposer.decompose(val);
    /// let rec = decomposer.recompose(dec);
    /// assert_eq!(decomposer.closest_representable(val), rec.unwrap());
    /// ```
    pub fn recompose(&self, decomp: SignedDecompositionIterNonNative<Scalar>) -> Option<Scalar> {
        if decomp.is_fresh() {
            let ciphertext_modulus_as_scalar =
                Scalar::cast_from(self.ciphertext_modulus.get_custom_modulus());
            Some(decomp.fold(Scalar::ZERO, |acc, term| {
                acc.wrapping_add_custom_mod(
                    term.to_recomposition_summand(),
                    ciphertext_modulus_as_scalar,
                )
            }))
        } else {
            None
        }
    }
}
