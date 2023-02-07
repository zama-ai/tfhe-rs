pub use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use dyn_stack::{DynArray, PodStack};
use std::iter::Map;
use std::slice::IterMut;

// copied from src/commons/math/decomposition/*.rs
// in order to avoid allocations

pub struct TensorSignedDecompositionLendingIter<'buffers, Scalar: UnsignedInteger> {
    // The base log of the decomposition
    base_log: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: Scalar,
    // The internal states of each decomposition
    states: DynArray<'buffers, Scalar>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
}

impl<'buffers, Scalar: UnsignedInteger> TensorSignedDecompositionLendingIter<'buffers, Scalar> {
    #[inline]
    pub(crate) fn new(
        input: impl Iterator<Item = Scalar>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        stack: PodStack<'buffers>,
    ) -> (Self, PodStack<'buffers>) {
        let shift = Scalar::BITS - base_log.0 * level.0;
        let (states, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, input.map(|i| i >> shift));
        (
            TensorSignedDecompositionLendingIter {
                base_log: base_log.0,
                current_level: level.0,
                mod_b_mask: (Scalar::ONE << base_log.0) - Scalar::ONE,
                states,
                fresh: true,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term<'short>(
        &'short mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        Map<IterMut<'short, Scalar>, impl FnMut(&'short mut Scalar) -> Scalar>,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        let current_level = self.current_level;
        let base_log = self.base_log;
        let mod_b_mask = self.mod_b_mask;
        self.current_level -= 1;

        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(self.base_log),
            self.states
                .iter_mut()
                .map(move |state| decompose_one_level(base_log, state, mod_b_mask)),
        ))
    }
}

#[inline]
fn decompose_one_level<S: UnsignedInteger>(base_log: usize, state: &mut S, mod_b_mask: S) -> S {
    let res = *state & mod_b_mask;
    *state >>= base_log;
    let mut carry = (res.wrapping_sub(S::ONE) | *state) & res;
    carry >>= base_log - 1;
    *state += carry;
    res.wrapping_sub(carry << base_log)
}
