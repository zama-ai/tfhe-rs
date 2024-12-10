use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecompositionIter, SignedDecompositionNonNativeIter, ValueSign,
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

/// With
///
/// B = 2^bit_count
/// val < B
/// random € [0, 1]
///
/// returns 1 if the following if condition is true otherwise 0
///
/// (val > B / 2) || ((val == B / 2) && (random == 1))
#[inline(always)]
fn balanced_rounding_condition_bit_trick<Scalar: UnsignedInteger>(
    val: Scalar,
    bit_count: usize,
    random: Scalar,
) -> Scalar {
    let shifted_random = random << (bit_count - 1);
    ((val.wrapping_sub(Scalar::ONE) | shifted_random) & val) >> (bit_count - 1)
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

    #[inline(always)]
    pub fn init_decomposer_state(&self, input: Scalar) -> Scalar {
        // The closest number representable by the decomposition can be computed by performing
        // the rounding at the appropriate bit.

        // We compute the number of least significant bits which can not be represented by the
        // decomposition
        // Example with level_count = 3, base_log = 4 and BITS == 64 -> 52
        let rep_bit_count = self.level_count * self.base_log;
        let non_rep_bit_count: usize = Scalar::BITS - rep_bit_count;
        // Move the representable bits + 1 to the LSB, with our example :
        //       |-----| 64 - (64 - 12 - 1) == 13 bits
        // 0....0XX...XX
        let mut res = input >> (non_rep_bit_count - 1);
        // Fetch the first bit value as we need it for a balanced rounding
        let rounding_bit = res & Scalar::ONE;
        // Add one to do the rounding by adding the half interval
        res += Scalar::ONE;
        // Discard the LSB which was the one deciding in which direction we round
        res >>= 1;
        // Keep the low base_log * level bits
        let mod_mask = Scalar::MAX >> (Scalar::BITS - rep_bit_count);
        res &= mod_mask;
        // Control bit about whether we should balance the state
        // This is equivalent to res > 2^(base_log * l) || (res == 2^(base_log * l) && random == 1)
        let need_balance = balanced_rounding_condition_bit_trick(res, rep_bit_count, rounding_bit);
        // Balance depending on the control bit
        res.wrapping_sub(need_balance << rep_bit_count)
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
            self.init_decomposer_state(input),
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_balanced_rounding_condition_as_bit_trick() {
        for rep_bit_count in 1..13 {
            println!("{rep_bit_count}");
            let b = 1u64 << rep_bit_count;
            let b_over_2 = b / 2;

            for val in 0..b {
                for random in [0, 1] {
                    let test_val = (val > b_over_2) || ((val == b_over_2) && (random == 1));
                    let bit_trick =
                        balanced_rounding_condition_bit_trick(val, rep_bit_count, random);
                    let bit_trick_as_bool = if bit_trick == 1 {
                        true
                    } else if bit_trick == 0 {
                        false
                    } else {
                        panic!("Bit trick result was not a bit.");
                    };

                    assert_eq!(
                        test_val, bit_trick_as_bool,
                        "val    ={val}\n\
                         val_b  ={val:064b}\n\
                         random ={random}\n\
                         expected: {test_val}\n\
                         got     : {bit_trick_as_bool}"
                    );
                }
            }
        }
    }
}
