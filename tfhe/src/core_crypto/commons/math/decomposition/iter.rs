use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

/// An iterator that yields the terms of the signed decomposition of an integer.
///
/// # Warning
///
/// This iterator yields the decomposition in reverse order. That means that the highest level
/// will be yielded first.
pub struct SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    // The base log of the decomposition
    base_log: usize,
    // The number of levels of the decomposition
    level_count: usize,
    // The internal state of the decomposition
    state: T,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: T,
    // A flag which store whether the iterator is a fresh one (for the recompose method)
    fresh: bool,
}

impl<T> SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    pub(crate) fn new(
        input: T,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
    ) -> SignedDecompositionIter<T> {
        SignedDecompositionIter {
            base_log: base_log.0,
            level_count: level.0,
            state: input >> (T::BITS - base_log.0 * level.0),
            current_level: level.0,
            mod_b_mask: (T::ONE << base_log.0) - T::ONE,
            fresh: true,
        }
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Returns the logarithm in base two of the base of this decomposition.
    ///
    /// If the decomposition uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let val = 1_340_987_234_u32;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Returns the number of levels of this decomposition.
    ///
    /// If the decomposition uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let val = 1_340_987_234_u32;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }
}

impl<T> Iterator for SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    type Item = DecompositionTerm<T>;

    fn next(&mut self) -> Option<Self::Item> {
        // The iterator is not fresh anymore
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        // We decompose the current level
        let output = decompose_one_level(self.base_log, &mut self.state, self.mod_b_mask);
        self.current_level -= 1;
        // We return the output for this level
        Some(DecompositionTerm::new(
            DecompositionLevel(self.current_level + 1),
            DecompositionBaseLog(self.base_log),
            output,
        ))
    }
}

fn decompose_one_level<S: UnsignedInteger>(base_log: usize, state: &mut S, mod_b_mask: S) -> S {
    let res = *state & mod_b_mask;
    *state >>= base_log;
    let mut carry = (res.wrapping_sub(S::ONE) | *state) & res;
    carry >>= base_log - 1;
    *state += carry;
    res.wrapping_sub(carry << base_log)
}
