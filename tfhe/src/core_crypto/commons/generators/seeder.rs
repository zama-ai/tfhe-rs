//! Module containing primitives pertaining to random generation in the context of seeds generation.

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, RandomGenerator, Seed, Seeder, Uniform,
};
use tfhe_csprng::seeders::SeedKind;

/// Seeder backed by a CSPRNG
///
/// ------------
/// ## Why this Seeder implementation?
///
/// [`Seeder`] is a trait available to the external user, and we expect some of them to implement
/// their own seeding strategy. Since this trait is public, it means that the implementer can be
/// arbitrarily slow. For this reason, it is better to only use it once when we initialize the
/// engine, and use the CSPRNG to generate other seeds when needed, because that gives us the
/// control on the performances.
///
/// ## Is it safe?
///
/// The answer to this question is the following: as long as the CSPRNG used in this [`Seeder`] is
/// seeded with a [`Seed`] coming from an entropy source then yes, seeding other CSPRNGs using this
/// CSPRNG is safe.
///
/// ## Why is it deterministic?
///
/// A CSPRNG is a Cryptograhically Secure Pseudo Random Number Generator.
///
/// Cryptographically Secure means that if one looks at the numbers it outputs, it looks exactly
/// like numbers drawn from a random distribution, this property is also known as "indistinguishable
/// from random". Here our CSPRNG outputs numbers uniformly so each value for a byte should appear
/// with the same probability.
///
/// Pseudo Random indicates that for the same initial state (here Seed) it will generate the same
/// exact set of numbers in the same order, making it deterministic.
pub struct DeterministicSeeder<G: ByteRandomGenerator> {
    generator: RandomGenerator<G>,
}

impl<G: ByteRandomGenerator> DeterministicSeeder<G> {
    pub fn new(seed: impl Into<SeedKind>) -> Self {
        let seed: SeedKind = seed.into();
        Self {
            generator: RandomGenerator::new(seed),
        }
    }
}

impl<G: ByteRandomGenerator> Seeder for DeterministicSeeder<G> {
    fn seed(&mut self) -> Seed {
        Seed(u128::generate_one(&mut self.generator, Uniform))
    }

    fn is_available() -> bool
    where
        Self: Sized,
    {
        true
    }
}
