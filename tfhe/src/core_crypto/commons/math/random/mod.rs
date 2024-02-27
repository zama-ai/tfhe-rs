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
use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev, Variance};
use crate::core_crypto::commons::numeric::{FloatingPoint, UnsignedInteger};

/// Convenience alias for the most efficient CSPRNG implementation available.
pub use activated_random_generator::ActivatedRandomGenerator;
pub use gaussian::*;
pub use generator::*;
pub use t_uniform::*;
pub use uniform::*;
pub use uniform_binary::*;
pub use uniform_ternary::*;

#[cfg(test)]
mod tests;

mod activated_random_generator;
mod gaussian;
mod generator;
mod t_uniform;
mod uniform;
mod uniform_binary;
mod uniform_ternary;

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
    use crate::core_crypto::commons::numeric::{FloatingPoint, UnsignedInteger};

    pub trait Sealed {}
    impl Sealed for super::Uniform {}
    impl Sealed for super::UniformBinary {}
    impl Sealed for super::UniformTernary {}
    impl<T: FloatingPoint> Sealed for super::Gaussian<T> {}
    impl<T: UnsignedInteger> Sealed for super::TUniform<T> {}
    impl<T: UnsignedInteger> Sealed for super::DynamicDistribution<T> {}
}
impl Distribution for Uniform {}
impl Distribution for UniformBinary {}
impl Distribution for UniformTernary {}
impl<T: FloatingPoint> Distribution for Gaussian<T> {}
impl<T: UnsignedInteger> Distribution for TUniform<T> {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DynamicDistribution<T: UnsignedInteger> {
    Gaussian(Gaussian<f64>),
    TUniform(TUniform<T>),
}

impl<T: UnsignedInteger> DynamicDistribution<T> {
    pub const fn new_gaussian_from_std_dev(std: StandardDev) -> Self {
        Self::Gaussian(Gaussian::from_standard_dev(std, 0.0))
    }

    pub fn new_gaussian(dispersion: impl DispersionParameter) -> Self {
        Self::Gaussian(Gaussian::from_standard_dev(
            StandardDev(dispersion.get_standard_dev()),
            0.0,
        ))
    }

    pub const fn new_t_uniform(bound_log2: u32) -> Self {
        Self::TUniform(TUniform::new(bound_log2))
    }

    #[track_caller]
    pub fn gaussian_variance(&self) -> Variance {
        match self {
            Self::Gaussian(gaussian) => {
                Variance(StandardDev::from_standard_dev(gaussian.std).get_variance())
            }
            Self::TUniform(_) => {
                panic!("Tried to get gaussian variance from a non gaussian distribution")
            }
        }
    }
}

impl<T: UnsignedInteger> std::fmt::Display for DynamicDistribution<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gaussian(Gaussian { std, mean }) => {
                // TODO: do we need to replace the "." by a "-" for some parameter name display?
                write!(f, "Gaussian(µ={mean},sigma={std})")
            }
            Self::TUniform(t_uniform) => {
                write!(f, "TUniform({})", t_uniform.bound_log2())
            }
        }
    }
}

impl<T: UnsignedInteger> Distribution for DynamicDistribution<T> {}

impl<
        T: UnsignedInteger
            + RandomGenerable<Gaussian<f64>, CustomModulus = T>
            + RandomGenerable<TUniform<T>, CustomModulus = T>,
    > RandomGenerable<DynamicDistribution<T>> for T
{
    type CustomModulus = Self;

    fn generate_one<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: DynamicDistribution<T>,
    ) -> Self {
        match distribution {
            DynamicDistribution::Gaussian(gaussian) => Self::generate_one(generator, gaussian),
            DynamicDistribution::TUniform(t_uniform) => Self::generate_one(generator, t_uniform),
        }
    }

    fn generate_one_custom_modulus<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: DynamicDistribution<T>,
        custom_modulus: Self::CustomModulus,
    ) -> Self {
        match distribution {
            DynamicDistribution::Gaussian(gaussian) => {
                Self::generate_one_custom_modulus(generator, gaussian, custom_modulus)
            }
            DynamicDistribution::TUniform(t_uniform) => {
                Self::generate_one_custom_modulus(generator, t_uniform, custom_modulus)
            }
        }
    }
}
