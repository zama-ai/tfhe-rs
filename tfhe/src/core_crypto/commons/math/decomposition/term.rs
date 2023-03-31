use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
use crate::core_crypto::commons::parameters::DecompositionBaseLog;
use std::fmt::Debug;

/// A member of the decomposition.
///
/// If we decompose a value $\theta$ as a sum $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$, this
/// represents a $\tilde{\theta}\_i$.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecompositionTerm<T>
where
    T: UnsignedInteger,
{
    level: usize,
    base_log: usize,
    value: T,
}

impl<T> DecompositionTerm<T>
where
    T: UnsignedInteger,
{
    // Creates a new decomposition term.
    pub(crate) fn new(level: DecompositionLevel, base_log: DecompositionBaseLog, value: T) -> Self {
        Self {
            level: level.0,
            base_log: base_log.0,
            value,
        }
    }

    /// Turn this term into a summand.
    ///
    /// If our member represents one $\tilde{\theta}\_i$ of the decomposition, this method returns
    /// $\tilde{\theta}\_i\frac{q}{B^i}$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
    /// assert_eq!(output.to_recomposition_summand(), 1048576);
    /// ```
    pub fn to_recomposition_summand(&self) -> T {
        let shift: usize = <T as Numeric>::BITS - self.base_log * self.level;
        self.value << shift
    }

    /// Return the value of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns its actual value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
    /// assert_eq!(output.value(), 1);
    /// ```
    pub fn value(&self) -> T {
        self.value
    }

    /// Return the level of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns the value of $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
    /// assert_eq!(output.level(), DecompositionLevel(3));
    /// ```
    pub fn level(&self) -> DecompositionLevel {
        DecompositionLevel(self.level)
    }
}

/// A member of the decomposition.
///
/// If we decompose a value $\theta$ as a sum $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$, this
/// represents a $\tilde{\theta}\_i$.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecompositionTermNonNative<T>
where
    T: UnsignedInteger,
{
    level: usize,
    base_log: usize,
    value: T,
    ciphertext_modulus: CiphertextModulus<T>,
}

impl<T> DecompositionTermNonNative<T>
where
    T: UnsignedInteger,
{
    // Creates a new decomposition term.
    pub(crate) fn new(
        level: DecompositionLevel,
        base_log: DecompositionBaseLog,
        value: T,
        ciphertext_modulus: CiphertextModulus<T>,
    ) -> Self {
        Self {
            level: level.0,
            base_log: base_log.0,
            value,
            ciphertext_modulus,
        }
    }

    /// Turn this term into a summand.
    ///
    /// If our member represents one $\tilde{\theta}\_i$ of the decomposition, this method returns
    /// $\tilde{\theta}\_i\frac{q}{B^i}$.
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
    ///     CiphertextModulus::try_new(1 << 32).unwrap(),
    /// );
    /// let output = decomposer.decompose(2u64.pow(19)).next().unwrap();
    /// assert_eq!(output.to_recomposition_summand(), 1048576);
    /// ```
    pub fn to_recomposition_summand(&self) -> T {
        // Floored approach
        // * floor(q / B^j)
        let base_to_the_level = 1 << (self.base_log * self.level);
        let digit_radix = self.ciphertext_modulus.get_custom_modulus() / base_to_the_level;

        let value_u128: u128 = self.value.cast_into();
        let summand_u128 = value_u128 * digit_radix;
        T::cast_from(summand_u128)
    }

    /// Return the value of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns its actual value.
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
    ///     CiphertextModulus::try_new(1 << 32).unwrap(),
    /// );
    /// let output = decomposer.decompose(2u64.pow(19)).next().unwrap();
    /// assert_eq!(output.value(), 1);
    /// ```
    pub fn value(&self) -> T {
        self.value
    }

    /// Return the level of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns the value of $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{
    ///     DecompositionLevel, SignedDecomposerNonNative,
    /// };
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new(1 << 32).unwrap(),
    /// );
    /// let output = decomposer.decompose(2u64.pow(19)).next().unwrap();
    /// assert_eq!(output.level(), DecompositionLevel(3));
    /// ```
    pub fn level(&self) -> DecompositionLevel {
        DecompositionLevel(self.level)
    }
}

/// A tensor whose elements are the terms of the decomposition of another tensor.
///
/// If we decompose each elements of a set of values $(\theta^{(a)})\_{a\in\mathbb{N}}$ as a set of
/// sums $(\sum\_{i=1}^l\tilde{\theta}^{(a)}\_i\frac{q}{B^i})\_{a\in\mathbb{N}}$, this represents a
/// set of $(\tilde{\theta}^{(a)}\_i)\_{a\in\mathbb{N}}$.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecompositionTermSlice<'a, Scalar>
where
    Scalar: UnsignedInteger,
{
    level: usize,
    base_log: usize,
    slice: &'a [Scalar],
}

impl<'a, Scalar> DecompositionTermSlice<'a, Scalar>
where
    Scalar: UnsignedInteger,
{
    // Creates a new tensor decomposition term.
    pub(crate) fn new(
        level: DecompositionLevel,
        base_log: DecompositionBaseLog,
        slice: &'a [Scalar],
    ) -> DecompositionTermSlice<Scalar> {
        DecompositionTermSlice {
            level: level.0,
            base_log: base_log.0,
            slice,
        }
    }

    /// Fills the output tensor with the terms turned to summands.
    ///
    /// If our term tensor represents a set of $(\tilde{\theta}^{(a)}\_i)\_{a\in\mathbb{N}}$ of the
    /// decomposition, this method fills the output tensor with a set of
    /// $(\tilde{\theta}^{(a)}\_i\frac{q}{B^i})\_{a\in\mathbb{N}}$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = vec![2u32.pow(19); 2];
    /// let mut decomp = decomposer.decompose_slice(&input);
    /// let term = decomp.next_term().unwrap();
    /// let mut output = vec![0, 2];
    /// term.fill_slice_with_recomposition_summand(&mut output);
    /// assert!(output.iter().all(|&x| x == 1048576));
    /// ```
    pub fn fill_slice_with_recomposition_summand(&self, output: &mut [Scalar]) {
        output
            .iter_mut()
            .zip(self.slice.iter())
            .for_each(|(dst, &value)| {
                let shift: usize = <Scalar as Numeric>::BITS - self.base_log * self.level;
                *dst = value << shift
            });
    }

    pub(crate) fn update_slice_with_recomposition_summand_wrapping_addition(
        &self,
        output: &mut [Scalar],
    ) {
        output
            .iter_mut()
            .zip(self.slice.iter())
            .for_each(|(out, &value)| {
                let shift: usize = <Scalar as Numeric>::BITS - self.base_log * self.level;
                *out = (*out).wrapping_add(value << shift);
            });
    }

    /// Returns a tensor with the values of term.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = vec![2u32.pow(19); 2];
    /// let mut decomp = decomposer.decompose_slice(&input);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(term.as_slice()[0], 1);
    /// ```
    pub fn as_slice(&self) -> &'a [Scalar] {
        self.slice
    }

    /// Returns the level of this decomposition term tensor.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = vec![2u32.pow(19); 2];
    /// let mut decomp = decomposer.decompose_slice(&input);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(term.level(), DecompositionLevel(3));
    /// ```
    pub fn level(&self) -> DecompositionLevel {
        DecompositionLevel(self.level)
    }
}
