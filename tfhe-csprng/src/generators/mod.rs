//! A module containing random generators objects.
//!
//! See [crate-level](`crate`) explanations.
use crate::seeders::Seed;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The number of children created when a generator is forked.
#[derive(Debug, Copy, Clone)]
pub struct ChildrenCount(pub usize);

/// The number of bytes each child can generate, when a generator is forked.
#[derive(Debug, Copy, Clone)]
pub struct BytesPerChild(pub usize);

/// A structure representing the number of bytes between two table indices.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct ByteCount(pub u128);

/// An error occurring during a generator fork.
#[derive(Debug)]
pub enum ForkError {
    ForkTooLarge,
    ZeroChildrenCount,
    ZeroBytesPerChild,
}

impl Display for ForkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ForkError::ForkTooLarge => {
                write!(
                    f,
                    "The children generators would output bytes after the parent bound. "
                )
            }
            ForkError::ZeroChildrenCount => {
                write!(
                    f,
                    "The number of children in the fork must be greater than zero."
                )
            }
            ForkError::ZeroBytesPerChild => {
                write!(
                    f,
                    "The number of bytes per child must be greater than zero."
                )
            }
        }
    }
}
impl Error for ForkError {}

/// A trait for cryptographically secure pseudo-random generators.
///
/// See the [crate-level](#crate) documentation for details.
pub trait RandomGenerator: Iterator<Item = u8> {
    /// The iterator over children generators, returned by `try_fork` in case of success.
    type ChildrenIter: Iterator<Item = Self>;

    /// Creates a new generator from a seed.
    ///
    /// This operation is usually costly to perform, as the aes round keys need to be generated from
    /// the seed.
    fn new(seed: Seed) -> Self;

    /// Returns the number of bytes that can still be outputted by the generator before reaching its
    /// bound.
    ///
    /// Note:
    /// -----
    ///
    /// A fresh generator can generate 2¹³² bytes. Unfortunately, no rust integer type in is able
    /// to encode such a large number. Consequently [`ByteCount`] uses the largest integer type
    /// available to encode this value: the `u128` type. For this reason, this method does not
    /// effectively return the number of remaining bytes, but instead
    /// `min(2¹²⁸-1, remaining_bytes)`.
    fn remaining_bytes(&self) -> ByteCount;

    /// Returns the next byte of the stream, if the generator did not yet reach its bound.
    fn next_byte(&mut self) -> Option<u8> {
        self.next()
    }

    /// Tries to fork the generator into an iterator of `n_children` new generators, each able to
    /// output `n_bytes` bytes.
    ///
    /// Note:
    /// -----
    ///
    /// To be successful, the number of remaining bytes for the parent generator must be larger than
    /// `n_children*n_bytes`.
    fn try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<Self::ChildrenIter, ForkError>;
}

/// A trait extending [`RandomGenerator`] to the parallel iterators of `rayon`.
#[cfg(feature = "parallel")]
pub trait ParallelRandomGenerator: RandomGenerator + Send {
    /// The iterator over children generators, returned by `par_try_fork` in case of success.
    type ParChildrenIter: rayon::prelude::IndexedParallelIterator<Item = Self>;

    /// Tries to fork the generator into a parallel iterator of `n_children` new generators, each
    /// able to output `n_bytes` bytes.
    ///
    /// Note:
    /// -----
    ///
    /// To be successful, the number of remaining bytes for the parent generator must be larger than
    /// `n_children*n_bytes`.
    fn par_try_fork(
        &mut self,
        n_children: ChildrenCount,
        n_bytes: BytesPerChild,
    ) -> Result<Self::ParChildrenIter, ForkError>;
}

mod aes_ctr;

mod implem;
pub use implem::*;

pub mod default;
/// Convenience alias for the most efficient CSPRNG implementation available.
pub use default::DefaultRandomGenerator;

#[cfg(test)]
#[allow(unused)] // to please clippy when tests are not activated
pub mod generator_generic_test {
    use super::*;
    use rand::Rng;

    const REPEATS: usize = 1_000;

    fn any_seed() -> impl Iterator<Item = Seed> {
        std::iter::repeat_with(|| Seed(rand::thread_rng().gen()))
    }

    fn some_children_count() -> impl Iterator<Item = ChildrenCount> {
        std::iter::repeat_with(|| ChildrenCount(rand::thread_rng().gen::<usize>() % 16 + 1))
    }

    fn some_bytes_per_child() -> impl Iterator<Item = BytesPerChild> {
        std::iter::repeat_with(|| BytesPerChild(rand::thread_rng().gen::<usize>() % 128 + 1))
    }

    /// Checks that the PRNG roughly generates uniform numbers.
    ///
    /// To do that, we perform an histogram of the occurrences of each byte value, over a fixed
    /// number of samples and check that the empirical probabilities of the bins are close to
    /// the theoretical probabilities.
    pub fn test_roughly_uniform<G: RandomGenerator>() {
        // Number of bins to use for the histogram.
        const N_BINS: usize = u8::MAX as usize + 1;
        // Number of samples to use for the histogram.
        let n_samples = 10_000_000_usize;
        // Theoretical probability of a each bins.
        let expected_prob: f64 = 1. / N_BINS as f64;
        // Absolute error allowed on the empirical probabilities.
        // This value was tuned to make the test pass on an arguably correct state of
        // implementation. 10^-4 precision is arguably pretty fine for this rough test, but it would
        // be interesting to improve this test.
        let precision = 10f64.powi(-3);

        for _ in 0..REPEATS {
            // We instantiate a new generator.
            let seed = any_seed().next().unwrap();
            let mut generator = G::new(seed);
            // We create a new histogram
            let mut counts = [0usize; N_BINS];
            // We fill the histogram.
            for _ in 0..n_samples {
                counts[generator.next_byte().unwrap() as usize] += 1;
            }
            // We check that the empirical probabilities are close enough to the theoretical one.
            counts
                .iter()
                .map(|a| (*a as f64) / (n_samples as f64))
                .for_each(|a| assert!((a - expected_prob).abs() < precision))
        }
    }

    /// Checks that given a state and a key, the PRNG is determinist.
    pub fn test_generator_determinism<G: RandomGenerator>() {
        for _ in 0..REPEATS {
            let seed = any_seed().next().unwrap();
            let mut first_generator = G::new(seed);
            let mut second_generator = G::new(seed);
            for _ in 0..1024 {
                assert_eq!(first_generator.next(), second_generator.next());
            }
        }
    }

    /// Checks that forks returns a bounded child, and that the proper number of bytes can be
    /// generated.
    pub fn test_fork_children<G: RandomGenerator>() {
        for _ in 0..REPEATS {
            let ((seed, n_children), n_bytes) = any_seed()
                .zip(some_children_count())
                .zip(some_bytes_per_child())
                .next()
                .unwrap();
            let mut gen = G::new(seed);
            let mut bounded = gen.try_fork(n_children, n_bytes).unwrap().next().unwrap();
            assert_eq!(bounded.remaining_bytes(), ByteCount(n_bytes.0 as u128));
            for _ in 0..n_bytes.0 {
                bounded.next().unwrap();
            }

            // Assert we are at the bound
            assert!(bounded.next().is_none());
        }
    }

    /// Checks that a bounded prng returns none when exceeding the allowed number of bytes.
    ///
    /// To properly check for panic use `#[should_panic(expected = "expected test panic")]` as an
    /// attribute on the test function.
    pub fn test_bounded_none_should_panic<G: RandomGenerator>() {
        let ((seed, n_children), n_bytes) = any_seed()
            .zip(some_children_count())
            .zip(some_bytes_per_child())
            .next()
            .unwrap();
        let mut gen = G::new(seed);
        let mut bounded = gen.try_fork(n_children, n_bytes).unwrap().next().unwrap();
        assert_eq!(bounded.remaining_bytes(), ByteCount(n_bytes.0 as u128));
        for _ in 0..n_bytes.0 {
            assert!(bounded.next().is_some());
        }

        // One call too many, should panic
        bounded.next().ok_or("expected test panic").unwrap();
    }
}
