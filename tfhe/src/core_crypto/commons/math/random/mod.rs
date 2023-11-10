//! A module containing random sampling functions.
//!
//! This module contains a [`RandomGenerator`] type, which exposes methods to sample numeric values
//! randomly according to a given distribution, for instance:
//!
//! + [`RandomGenerator::random_uniform`] samples a random unsigned integer with uniform
//! probability over the set of representable values.
//! + [`RandomGenerator::random_gaussian`] samples a random float with using a gaussian
//! distribution.
//!
//! The implementation relies on the [`RandomGenerable`] trait, which gives a type the ability to
//! be randomly generated according to a given distribution. The module contains multiple
//! implementations of this trait, for different distributions. Note, though, that instead of
//! using the [`RandomGenerable`] methods, you should use the various methods exposed by
//! [`RandomGenerator`] instead.
use crate::core_crypto::commons::numeric::FloatingPoint;

/// Convenience alias for the most efficient CSPRNG implementation available.
pub use activated_random_generator::ActivatedRandomGenerator;
pub use gaussian::*;
pub use generator::*;
pub use uniform::*;
pub use uniform_binary::*;
pub use uniform_lsb::*;
pub use uniform_msb::*;
pub use uniform_ternary::*;
pub use uniform_with_zeros::*;

#[cfg(test)]
mod tests;

mod activated_random_generator;
mod gaussian;
mod generator;
mod uniform;
mod uniform_binary;
mod uniform_lsb;
mod uniform_msb;
mod uniform_ternary;
mod uniform_with_zeros;

/// A trait giving a type the ability to be randomly generated according to a given distribution.
pub trait RandomGenerable<D: Distribution>
where
    Self: Sized,
{
    // This is required as e.g. Gaussian can generate pairs of Torus elements and we can't use a
    // pair of elements as custom modulus
    type CustomModulus: Copy;

    fn generate_one<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: D,
    ) -> Self;

    fn generate_one_custom_modulus<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: D,
        custom_modulus: Self::CustomModulus,
    ) -> Self {
        let _ = generator;
        let _ = distribution;
        let _ = custom_modulus;
        todo!("This distribution does not support custom modulus generation at this time.");
    }

    fn fill_slice<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: D,
        slice: &mut [Self],
    ) {
        for s in slice.iter_mut() {
            *s = Self::generate_one(generator, distribution);
        }
    }

    fn fill_slice_custom_mod<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: D,
        slice: &mut [Self],
        custom_modulus: Self::CustomModulus,
    ) {
        for s in slice.iter_mut() {
            *s = Self::generate_one_custom_modulus(generator, distribution, custom_modulus);
        }
    }
}

/// A marker trait for types representing distributions.
pub trait Distribution: seal::Sealed + Copy {}
mod seal {
    use crate::core_crypto::commons::numeric::FloatingPoint;

    pub trait Sealed {}
    impl Sealed for super::Uniform {}
    impl Sealed for super::UniformMsb {}
    impl Sealed for super::UniformLsb {}
    impl Sealed for super::UniformWithZeros {}
    impl Sealed for super::UniformBinary {}
    impl Sealed for super::UniformTernary {}
    impl<T: FloatingPoint> Sealed for super::Gaussian<T> {}
}
impl Distribution for Uniform {}
impl Distribution for UniformMsb {}
impl Distribution for UniformLsb {}
impl Distribution for UniformWithZeros {}
impl Distribution for UniformBinary {}
impl Distribution for UniformTernary {}
impl<T: FloatingPoint> Distribution for Gaussian<T> {}
