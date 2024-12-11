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

    /// Return the value of the term. For the native modulus it is also the modular value of the
    /// term.
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
/// If we decompose a value $\theta$ as a sum
/// $\sum\_{i=1}^l\tilde{\theta}\_i\frac{v}{B^i}$, where $\lambda = \lceil{\log_2{q}}\rceil$ and
/// $ v = 2^{\lambda} $. this represents a $\tilde{\theta}\_i$.
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
    /// Creates a new decomposition term.
    ///
    /// The value is the actual (non modular) value of the decomposition term.
    ///
    /// To get the actual modular value for the given `ciphertext_modulus` use
    /// [`Self::modular_value`].
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
    /// $\tilde{\theta}\_i\frac{v}{B^i}$ where $\lambda = \lceil{\log_2{q}}\rceil$ and
    /// $ v = 2^{\lambda} $.
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
    /// let output = decomposer.decompose(2u64.pow(52)).next().unwrap();
    /// assert_eq!(output.to_approximate_recomposition_summand(), 2u64.pow(52));
    /// ```
    pub fn to_approximate_recomposition_summand(&self) -> T {
        let modulus_as_t = T::cast_from(self.ciphertext_modulus.get_custom_modulus());
        let ciphertext_modulus_bit_count: usize = modulus_as_t.ceil_ilog2().try_into().unwrap();
        let shift: usize = ciphertext_modulus_bit_count - self.base_log * self.level;

        let value = self.value;
        if value.into_signed() >= T::Signed::ZERO {
            value << shift
        } else {
            modulus_as_t.wrapping_add(value << shift)
        }
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
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let output = decomposer.decompose(2u64.pow(52)).next().unwrap();
    /// assert_eq!(output.value(), 1);
    /// ```
    pub fn value(&self) -> T {
        self.value
    }

    /// Return the value of the term modulo the modulus given when building the
    /// [`DecompositionTermNonNative`].
    pub fn modular_value(&self) -> T {
        let value = self.value;
        if value.into_signed() >= T::Signed::ZERO {
            value
        } else {
            let modulus_as_t = T::cast_from(self.ciphertext_modulus.get_custom_modulus());
            modulus_as_t.wrapping_add(value)
        }
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
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let output = decomposer.decompose(2u64.pow(52)).next().unwrap();
    /// assert_eq!(output.level(), DecompositionLevel(3));
    /// ```
    pub fn level(&self) -> DecompositionLevel {
        DecompositionLevel(self.level)
    }
}
