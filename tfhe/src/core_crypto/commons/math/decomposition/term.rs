use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::tensor::{AsMutTensor, Tensor};
use crate::core_crypto::commons::numeric::{Numeric, UnsignedInteger};
use crate::core_crypto::prelude::DecompositionBaseLog;
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A member of the decomposition.
///
/// If we decompose a value $\theta$ as a sum $\sum\_{i=1}^l\tilde{\theta}\_i\frac{q}{B^i}$, this
/// represents a $\tilde{\theta}\_i$.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
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
    pub(crate) fn new(
        level: DecompositionLevel,
        base_log: DecompositionBaseLog,
        value: T,
    ) -> DecompositionTerm<T> {
        DecompositionTerm {
            level: level.0,
            base_log: base_log.0,
            value,
        }
    }

    /// Turns this term into a summand.
    ///
    /// If our member represents one $\tilde{\theta}\_i$ of the decomposition, this method returns
    /// $\tilde{\theta}\_i\frac{q}{B^i}$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
    /// assert_eq!(output.to_recomposition_summand(), 1048576);
    /// ```
    pub fn to_recomposition_summand(&self) -> T {
        let shift: usize = <T as Numeric>::BITS - self.base_log * self.level;
        self.value << shift
    }

    /// Returns the value of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns its actual value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
    /// assert_eq!(output.value(), 1);
    /// ```
    pub fn value(&self) -> T {
        self.value
    }

    /// Returns the level of the term.
    ///
    /// If our member represents one $\tilde{\theta}\_i$, this returns the value of $i$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let output = decomposer.decompose(2u32.pow(19)).next().unwrap();
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
pub struct DecompositionTermTensor<'a, Scalar>
where
    Scalar: UnsignedInteger,
{
    level: usize,
    base_log: usize,
    tensor: Tensor<&'a [Scalar]>,
}

impl<'a, Scalar> DecompositionTermTensor<'a, Scalar>
where
    Scalar: UnsignedInteger,
{
    // Creates a new tensor decomposition term.
    pub(crate) fn new(
        level: DecompositionLevel,
        base_log: DecompositionBaseLog,
        tensor: Tensor<&'a [Scalar]>,
    ) -> DecompositionTermTensor<Scalar> {
        DecompositionTermTensor {
            level: level.0,
            base_log: base_log.0,
            tensor,
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
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = Tensor::allocate(2u32.pow(19), 1);
    /// let mut decomp = decomposer.decompose_tensor(&input);
    /// let term = decomp.next_term().unwrap();
    /// let mut output = Tensor::allocate(0, 1);
    /// term.fill_tensor_with_recomposition_summand(&mut output);
    /// assert_eq!(*output.get_element(0), 1048576);
    /// ```
    pub fn fill_tensor_with_recomposition_summand<TLike>(&self, output: &mut TLike)
    where
        TLike: AsMutTensor<Element = Scalar>,
    {
        output.as_mut_tensor().fill_with_one(&self.tensor, |value| {
            let shift: usize = <Scalar as Numeric>::BITS - self.base_log * self.level;
            *value << shift
        });
    }

    pub(crate) fn update_tensor_with_recomposition_summand_wrapping_addition<TLike>(
        &self,
        output: &mut TLike,
    ) where
        TLike: AsMutTensor<Element = Scalar>,
    {
        output
            .as_mut_tensor()
            .update_with_one(&self.tensor, |out, value| {
                let shift: usize = <Scalar as Numeric>::BITS - self.base_log * self.level;
                *out = out.wrapping_add(*value << shift);
            });
    }

    /// Returns a tensor with the values of term.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = Tensor::allocate(2u32.pow(19), 1);
    /// let mut decomp = decomposer.decompose_tensor(&input);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(*term.as_tensor().get_element(0), 1);
    /// ```
    pub fn as_tensor(&self) -> &Tensor<&'a [Scalar]> {
        &self.tensor
    }

    /// Returns the level of this decomposition term tensor.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
    /// use tfhe::core_crypto::commons::math::tensor::Tensor;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let input = Tensor::allocate(2u32.pow(19), 1);
    /// let mut decomp = decomposer.decompose_tensor(&input);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(term.level(), DecompositionLevel(3));
    /// ```
    pub fn level(&self) -> DecompositionLevel {
        DecompositionLevel(self.level)
    }
}
