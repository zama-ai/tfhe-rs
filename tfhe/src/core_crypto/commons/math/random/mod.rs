//! A module containing random sampling functions.
//!
//! This module contains a [`RandomGenerator`] type, which exposes methods to sample numeric values
//! randomly according to a given distribution, for instance:
//!
//! + [`RandomGenerator::random_uniform`] samples a random unsigned integer with uniform probability
//!   over the set of representable values.
//! + [`RandomGenerator::random_gaussian`] samples a random float with using a gaussian
//!   distribution.
//!
//! The implementation relies on the [`RandomGenerable`] trait, which gives a type the ability to
//! be randomly generated according to a given distribution. The module contains multiple
//! implementations of this trait, for different distributions. Note, though, that instead of
//! using the [`RandomGenerable`] methods, you should use the various methods exposed by
//! [`RandomGenerator`] instead.
use crate::core_crypto::backward_compatibility::commons::math::random::DynamicDistributionVersions;
use crate::core_crypto::commons::dispersion::{DispersionParameter, StandardDev, Variance};
use crate::core_crypto::commons::numeric::{FloatingPoint, UnsignedInteger};
use std::ops::Bound;

use crate::core_crypto::prelude::{CastInto, Numeric};
pub use gaussian::*;
pub use generator::*;
pub use t_uniform::*;
pub use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_versionable::Versionize;
pub use uniform::*;
pub use uniform_binary::*;
pub use uniform_ternary::*;

#[cfg(test)]
mod tests;

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

    /// Return the probability to successfully generate a sample from the given distribution for the
    /// type the trait is implemented on.
    ///
    /// If the generation can never fail it should return 1.0, otherwise it returns a value in
    /// ]0; 1[.
    ///
    /// If None is passed for modulus, then the native modulus of the type (e.g. $2^{64}$ for u64)
    /// or no modulus for floating points values is used.
    ///
    /// Otherwise the given modulus is interpreted as being the one used for a call to
    /// [`RandomGenerable::generate_one_custom_modulus`].
    fn single_sample_success_probability(
        distribution: D,
        modulus: Option<Self::CustomModulus>,
    ) -> f64;

    /// Return how many bytes coming from a CSPRNG are required to generate one sample even if that
    /// generation can fail.
    ///
    /// If None is passed for modulus, then the native modulus of the type (e.g. $2^{64}$ for u64)
    /// or no modulus for floating points values is used.
    ///
    /// Otherwise the given modulus is interpreted as being the one used for a call to
    /// [`RandomGenerable::generate_one_custom_modulus`].
    fn single_sample_required_random_byte_count(
        distribution: D,
        modulus: Option<Self::CustomModulus>,
    ) -> usize;
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

pub trait BoundedDistribution<T>: Distribution {
    fn low_bound(&self) -> Bound<T>;
    fn high_bound(&self) -> Bound<T>;

    fn contains(self, value: T) -> bool
    where
        T: Numeric,
    {
        {
            match self.low_bound() {
                Bound::Included(inclusive_low) => {
                    if value < inclusive_low {
                        return false;
                    }
                }
                Bound::Excluded(exclusive_low) => {
                    if value <= exclusive_low {
                        return false;
                    }
                }
                Bound::Unbounded => {}
            }
        }

        {
            match self.high_bound() {
                Bound::Included(inclusive_high) => {
                    if value > inclusive_high {
                        return false;
                    }
                }
                Bound::Excluded(exclusive_high) => {
                    if value >= exclusive_high {
                        return false;
                    }
                }
                Bound::Unbounded => {}
            }
        }

        true
    }
}

impl<T> BoundedDistribution<T::Signed> for TUniform<T>
where
    T: UnsignedInteger,
{
    fn low_bound(&self) -> Bound<T::Signed> {
        Bound::Included(self.min_value_inclusive())
    }

    fn high_bound(&self) -> Bound<T::Signed> {
        Bound::Included(self.max_value_inclusive())
    }
}

impl<T> BoundedDistribution<T::Signed> for DynamicDistribution<T>
where
    T: UnsignedInteger,
{
    fn low_bound(&self) -> Bound<T::Signed> {
        match self {
            Self::Gaussian(_) => Bound::Unbounded,
            Self::TUniform(tu) => tu.low_bound(),
        }
    }

    fn high_bound(&self) -> Bound<T::Signed> {
        match self {
            Self::Gaussian(_) => Bound::Unbounded,
            Self::TUniform(tu) => tu.high_bound(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Versionize)]
#[versionize(DynamicDistributionVersions)]
pub enum DynamicDistribution<T: UnsignedInteger> {
    Gaussian(Gaussian<f64>),
    TUniform(TUniform<T>),
}

impl<T: UnsignedInteger> DynamicDistribution<T> {
    pub const fn new_gaussian_from_std_dev(std: StandardDev) -> Self {
        Self::Gaussian(Gaussian::from_standard_dev(std, 0.0))
    }

    pub fn new_gaussian(dispersion: impl DispersionParameter) -> Self {
        Self::Gaussian(Gaussian::from_dispersion_parameter(dispersion, 0.0))
    }

    #[track_caller]
    pub const fn new_t_uniform(bound_log2: u32) -> Self {
        Self::TUniform(TUniform::new(bound_log2))
    }

    #[track_caller]
    pub const fn try_new_t_uniform(bound_log2: u32) -> Result<Self, &'static str> {
        match TUniform::try_new(bound_log2) {
            Ok(ok) => Ok(Self::TUniform(ok)),
            Err(e) => Err(e),
        }
    }

    #[track_caller]
    pub const fn gaussian_std_dev(&self) -> StandardDev {
        match self {
            Self::Gaussian(gaussian) => StandardDev(gaussian.std),
            Self::TUniform(_) => {
                panic!("Tried to get gaussian variance from a non gaussian distribution")
            }
        }
    }

    #[track_caller]
    pub fn gaussian_variance(&self) -> Variance {
        match self {
            Self::Gaussian(gaussian) => StandardDev::from_standard_dev(gaussian.std).get_variance(),
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

    fn single_sample_success_probability(
        distribution: DynamicDistribution<T>,
        modulus: Option<Self::CustomModulus>,
    ) -> f64 {
        match distribution {
            DynamicDistribution::Gaussian(gaussian) => {
                <Self as RandomGenerable<Gaussian<f64>>>::single_sample_success_probability(
                    gaussian, modulus,
                )
            }
            DynamicDistribution::TUniform(t_uniform) => {
                <Self as RandomGenerable<TUniform<T>>>::single_sample_success_probability(
                    t_uniform, modulus,
                )
            }
        }
    }

    fn single_sample_required_random_byte_count(
        distribution: DynamicDistribution<T>,
        modulus: Option<Self::CustomModulus>,
    ) -> usize {
        match distribution {
            DynamicDistribution::Gaussian(gaussian) => {
                <Self as RandomGenerable<Gaussian<f64>>>::single_sample_required_random_byte_count(
                    gaussian, modulus,
                )
            }
            DynamicDistribution::TUniform(t_uniform) => {
                <Self as RandomGenerable<TUniform<T>>>::single_sample_required_random_byte_count(
                    t_uniform, modulus,
                )
            }
        }
    }
}
