//! A module containing random generators objects.
//!
//! See [crate-level](`crate`) explanations.
use crate::seeders::SeedKind;
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
    fn new(seed: impl Into<SeedKind>) -> Self;

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
    use crate::seeders::{Seed, XofSeed};
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

    pub fn test_vectors<G: RandomGenerator>() {
        // Number of random bytes to generate,
        // this should be 2 batch worth of aes calls (where a batch is 8 aes)
        const N_BYTES: usize = 16 * 2 * 8;

        const EXPECTED_BYTE: [u8; N_BYTES] = [
            14, 216, 93, 249, 97, 26, 187, 114, 73, 205, 209, 104, 197, 70, 126, 250, 235, 1, 136,
            141, 46, 146, 174, 231, 14, 204, 28, 99, 139, 246, 214, 112, 253, 151, 34, 114, 235, 7,
            76, 37, 36, 154, 226, 148, 68, 238, 117, 87, 212, 183, 174, 200, 222, 153, 62, 48, 166,
            134, 27, 97, 230, 206, 78, 128, 151, 166, 15, 156, 120, 158, 35, 41, 121, 55, 180, 184,
            108, 160, 33, 208, 255, 147, 246, 159, 10, 239, 6, 103, 124, 123, 83, 72, 189, 237,
            225, 36, 30, 151, 134, 94, 211, 181, 108, 239, 137, 18, 246, 237, 233, 59, 61, 24, 111,
            198, 76, 92, 86, 129, 171, 50, 124, 2, 72, 143, 160, 223, 32, 187, 175, 239, 111, 51,
            85, 110, 134, 45, 193, 113, 247, 249, 78, 230, 103, 123, 66, 48, 31, 169, 228, 140,
            202, 168, 202, 199, 147, 89, 135, 104, 254, 198, 72, 31, 103, 236, 207, 138, 24, 100,
            230, 168, 233, 214, 130, 195, 0, 25, 220, 136, 128, 173, 40, 154, 116, 87, 114, 187,
            170, 150, 131, 163, 155, 98, 217, 198, 238, 178, 165, 214, 168, 252, 107, 123, 214, 33,
            17, 114, 35, 23, 172, 145, 5, 39, 16, 33, 92, 163, 132, 240, 167, 128, 226, 165, 80, 9,
            153, 252, 139, 0, 139, 0, 54, 188, 253, 141, 2, 78, 97, 53, 214, 173, 155, 84, 98, 51,
            70, 110, 91, 181, 229, 231, 27, 225, 185, 143, 63, 238,
        ];

        let seed_bytes: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let seed = Seed(u128::from_ne_bytes(seed_bytes));

        let mut rng = G::new(seed);
        let bytes = rng.take(N_BYTES).collect::<Vec<_>>();
        assert_eq!(bytes, EXPECTED_BYTE);
    }

    pub fn test_vectors_xof_seed<G: RandomGenerator>() {
        // Number of random bytes to generate,
        // this should be 2 batch worth of aes calls (where a batch is 8 aes)
        const N_BYTES: usize = 16 * 2 * 8;

        const EXPECTED_BYTE: [u8; N_BYTES] = [
            134, 231, 117, 200, 60, 174, 158, 95, 80, 64, 236, 147, 204, 196, 251, 198, 110, 155,
            74, 69, 162, 251, 224, 46, 46, 83, 209, 224, 89, 108, 68, 240, 37, 16, 109, 194, 92, 3,
            164, 21, 167, 224, 205, 31, 90, 178, 59, 150, 142, 238, 113, 144, 181, 118, 160, 72,
            187, 38, 29, 61, 189, 229, 66, 22, 4, 38, 210, 63, 232, 182, 115, 49, 96, 6, 120, 226,
            40, 51, 144, 59, 136, 224, 252, 195, 50, 250, 134, 45, 149, 220, 32, 27, 35, 225, 190,
            73, 161, 182, 250, 149, 153, 131, 220, 143, 181, 152, 187, 25, 62, 197, 24, 10, 142,
            57, 172, 15, 17, 244, 242, 232, 51, 50, 244, 85, 58, 69, 28, 113, 151, 143, 138, 166,
            198, 16, 210, 46, 234, 138, 32, 124, 98, 167, 141, 251, 60, 13, 158, 106, 29, 86, 63,
            73, 42, 138, 174, 195, 192, 72, 122, 74, 54, 134, 107, 144, 241, 12, 33, 70, 27, 116,
            154, 123, 1, 252, 141, 73, 79, 30, 162, 43, 57, 8, 99, 62, 222, 117, 232, 147, 81, 189,
            54, 17, 233, 33, 41, 132, 155, 246, 185, 189, 17, 77, 32, 107, 134, 61, 174, 64, 174,
            80, 229, 239, 243, 143, 152, 249, 254, 125, 42, 0, 170, 253, 34, 57, 100, 82, 244, 9,
            101, 126, 138, 218, 215, 55, 58, 177, 154, 5, 28, 113, 89, 123, 129, 254, 212, 191,
            162, 44, 120, 67, 241, 157, 31, 162, 113, 91,
        ];

        let seed_bytes: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let seed = u128::from_ne_bytes(seed_bytes);
        let xof_seed = XofSeed::new_u128(seed, [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h']);

        let mut rng = G::new(xof_seed);
        let bytes = rng.take(N_BYTES).collect::<Vec<_>>();
        assert_eq!(bytes, EXPECTED_BYTE);
    }
}
