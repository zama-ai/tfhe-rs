use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, Gaussian, RandomGenerable, RandomGenerator, Seed,
};
use crate::core_crypto::commons::math::tensor::Tensor;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::prelude::DispersionParameter;

/// A random number generator which can be used to generate secret keys.
pub struct SecretRandomGenerator<G: ByteRandomGenerator>(RandomGenerator<G>);

impl<G: ByteRandomGenerator> SecretRandomGenerator<G> {
    /// Creates a new generator, optionally seeding it with the given value.
    pub fn new(seed: Seed) -> SecretRandomGenerator<G> {
        SecretRandomGenerator(RandomGenerator::new(seed))
    }

    /// Returns the number of remaining bytes, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.0.remaining_bytes()
    }

    // Returns a tensor with random uniform binary values.
    pub(crate) fn random_binary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_binary_tensor(length)
    }

    // Returns a tensor with random uniform ternary values.
    pub(crate) fn random_ternary_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_ternary_tensor(length)
    }

    // Returns a tensor with random uniform values.
    pub(crate) fn random_uniform_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        Scalar: UnsignedTorus,
    {
        self.0.random_uniform_tensor(length)
    }

    // Returns a tensor with random gaussian values.
    pub(crate) fn random_gaussian_tensor<Scalar>(&mut self, length: usize) -> Tensor<Vec<Scalar>>
    where
        (Scalar, Scalar): RandomGenerable<Gaussian<f64>>,
        Scalar: UnsignedTorus,
    {
        self.0
            .random_gaussian_tensor(length, 0.0, Scalar::GAUSSIAN_KEY_LOG_STD.get_standard_dev())
    }
}
