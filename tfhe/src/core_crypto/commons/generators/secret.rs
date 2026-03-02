//! Module containing primitives pertaining to random generation in the context of secret key
//! generation.

use tfhe_csprng::seeders::SeedKind;

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, RandomGenerator, UniformBinary,
};
use crate::core_crypto::prelude::{NormalizedHammingWeightBound, UnsignedInteger};

/// A random number generator which can be used to generate secret keys.
pub struct SecretRandomGenerator<G: ByteRandomGenerator>(RandomGenerator<G>);

impl<G: ByteRandomGenerator> SecretRandomGenerator<G> {
    /// Create a new generator, optionally seeding it with the given value.
    pub fn new(seed: impl Into<SeedKind>) -> Self {
        let seed: SeedKind = seed.into();
        Self(RandomGenerator::new(seed))
    }

    pub fn from_raw_parts(inner: RandomGenerator<G>) -> Self {
        Self(inner)
    }

    pub fn into_raw_parts(self) -> RandomGenerator<G> {
        self.0
    }

    /// Return the number of remaining bytes, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.0.remaining_bytes()
    }

    pub(crate) fn fill_slice_with_random_uniform_binary<Scalar>(&mut self, slice: &mut [Scalar])
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        self.0.fill_slice_with_random_uniform_binary(slice);
    }

    pub(crate) fn generate_random_uniform_binary<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        self.0.random_uniform_binary()
    }

    pub fn fill_slice_with_random_uniform_binary_bits<Scalar>(&mut self, output: &mut [Scalar])
    where
        Scalar: UnsignedInteger,
    {
        self.0.fill_slice_with_random_uniform_binary_bits(output);
    }

    /// Fills the slice with uniform binary random, such that the
    /// hamming weight of the output is ok with regards to the max normalized hamming weight
    ///
    /// This will loop and reject slices until an ok sequence of random binary was generated
    pub fn fill_slice_with_bounded_random_uniform_binary_bits<Scalar>(
        &mut self,
        output: &mut [Scalar],
        max_norm_hwt: NormalizedHammingWeightBound,
    ) where
        Scalar: UnsignedInteger,
    {
        loop {
            self.0.fill_slice_with_random_uniform_binary_bits(output);

            if max_norm_hwt.check_binary_slice(output).is_ok() {
                break;
            }
        }
    }
}
