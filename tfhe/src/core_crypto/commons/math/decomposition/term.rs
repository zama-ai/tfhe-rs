use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
use crate::core_crypto::commons::parameters::DecompositionBaseLog;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A member of the decomposition.
///
/// If we decompose a value $\theta$ as a sum $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$, this
/// represents a $\tilde{\theta}\_i$.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
