use super::*;
use crate::core_crypto::backward_compatibility::commons::math::random::GaussianVersions;
use crate::core_crypto::commons::math::torus::FromTorus;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

// Clippy false positive, does not repro with smaller code
#[allow(clippy::derive_partial_eq_without_eq)]
/// A distribution type representing random sampling of floating point numbers, following a
/// gaussian distribution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Versionize)]
#[versionize(GaussianVersions)]
pub struct Gaussian<T: FloatingPoint> {
    /// The standard deviation of the distribution.
    pub std: T,
    /// The mean of the distribution.
    pub mean: T,
}

impl Gaussian<f64> {
    pub const fn from_standard_dev(std: StandardDev, mean: f64) -> Self {
        Self { std: std.0, mean }
    }

    pub fn from_dispersion_parameter(dispersion: impl DispersionParameter, mean: f64) -> Self {
        Self {
            std: dispersion.get_standard_dev().0,
            mean,
        }
    }

    pub fn standard_dev(&self) -> StandardDev {
        StandardDev(self.std)
    }
}

macro_rules! implement_gaussian {
    ($T:ty, $S:ty) => {
        impl RandomGenerable<Gaussian<$T>> for ($T, $T) {
            type CustomModulus = $T;
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                Gaussian { std, mean }: Gaussian<$T>,
            ) -> Self {
                let output: ($T, $T);
                let mut uniform_rand_bytes_u = [0u8; std::mem::size_of::<$S>()];
                let mut uniform_rand_bytes_v = [0u8; std::mem::size_of::<$S>()];
                loop {
                    uniform_rand_bytes_u
                        .iter_mut()
                        .for_each(|a| *a = generator.generate_next());
                    uniform_rand_bytes_v
                        .iter_mut()
                        .for_each(|a| *a = generator.generate_next());
                    let size = <$T>::BITS as i32;
                    let mut u: $T = <$S>::from_le_bytes(uniform_rand_bytes_u).cast_into();
                    u *= <$T>::TWO.powi(-size + 1);
                    let mut v: $T = <$S>::from_le_bytes(uniform_rand_bytes_v).cast_into();
                    v *= <$T>::TWO.powi(-size + 1);
                    let s = u.powi(2) + v.powi(2);
                    if (s > <$T>::ZERO && s < <$T>::ONE) {
                        let cst = std * (-<$T>::TWO * s.ln() / s).sqrt();
                        output = (u * cst + mean, v * cst + mean);
                        break;
                    }
                }
                output
            }

            fn single_sample_success_probability(
                _distribution: Gaussian<$T>,
                _modulus: Option<Self::CustomModulus>,
            ) -> f64 {
                // The modulus and parameters of the distribution do not impact generation success
                // The sample is valid if it's in the circle of radius pi and
                // Samples are drawn in a 2 by 2 square, use area(circle) / area(square) as
                // probability
                std::f64::consts::PI / 4.0
            }

            fn single_sample_required_random_byte_count(
                _distribution: Gaussian<$T>,
                _modulus: Option<Self::CustomModulus>,
            ) -> usize {
                // The modulus and parameters of the distribution do not impact the amount of byte
                // required
                2 * std::mem::size_of::<$S>()
            }
        }
    };
}

implement_gaussian!(f32, i32);
implement_gaussian!(f64, i64);

impl<Torus> RandomGenerable<Gaussian<f64>> for (Torus, Torus)
where
    Torus: FromTorus<f64>,
{
    type CustomModulus = Torus;

    fn generate_one<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: Gaussian<f64>,
    ) -> Self {
        let (s1, s2) = <(f64, f64)>::generate_one(generator, distribution);
        (
            <Torus as FromTorus<f64>>::from_torus(s1),
            <Torus as FromTorus<f64>>::from_torus(s2),
        )
    }

    fn generate_one_custom_modulus<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: Gaussian<f64>,
        custom_modulus: Self::CustomModulus,
    ) -> Self {
        let (s1, s2) = <(f64, f64)>::generate_one(generator, distribution);
        (
            <Torus as FromTorus<f64>>::from_torus_custom_mod(s1, custom_modulus),
            <Torus as FromTorus<f64>>::from_torus_custom_mod(s2, custom_modulus),
        )
    }

    fn single_sample_success_probability(
        distribution: Gaussian<f64>,
        _modulus: Option<Self::CustomModulus>,
    ) -> f64 {
        // Here the CustomModulus is a Torus and not f64 and is therefore not compatible, so
        // we cannot forward it, thankully the modulus does not impact gaussian generation success
        <(f64, f64) as RandomGenerable<Gaussian<f64>>>::single_sample_success_probability(
            distribution,
            None,
        )
    }

    fn single_sample_required_random_byte_count(
        distribution: Gaussian<f64>,
        _modulus: Option<Self::CustomModulus>,
    ) -> usize {
        // Here the CustomModulus is a Torus and not f64 and is therefore not compatible, so
        // we cannot forward it, thankully the modulus does not impact gaussian generation success
        <(f64, f64) as RandomGenerable<Gaussian<f64>>>::single_sample_required_random_byte_count(
            distribution,
            None,
        )
    }
}

impl<Torus> RandomGenerable<Gaussian<f64>> for Torus
where
    Torus: FromTorus<f64>,
{
    type CustomModulus = Torus;

    fn generate_one<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: Gaussian<f64>,
    ) -> Self {
        let (s1, _) = <(f64, f64)>::generate_one(generator, distribution);
        <Torus as FromTorus<f64>>::from_torus(s1)
    }

    fn generate_one_custom_modulus<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: Gaussian<f64>,
        custom_modulus: Self::CustomModulus,
    ) -> Self {
        let (s1, _) = <(f64, f64)>::generate_one(generator, distribution);
        <Torus as FromTorus<f64>>::from_torus_custom_mod(s1, custom_modulus)
    }

    fn single_sample_success_probability(
        distribution: Gaussian<f64>,
        _modulus: Option<Self::CustomModulus>,
    ) -> f64 {
        // Here the CustomModulus is a Torus and not f64 and is therefore not compatible, so
        // we cannot forward it, thankully the modulus does not impact gaussian generation success
        <(f64, f64) as RandomGenerable<Gaussian<f64>>>::single_sample_success_probability(
            distribution,
            None,
        )
    }

    fn single_sample_required_random_byte_count(
        distribution: Gaussian<f64>,
        _modulus: Option<Self::CustomModulus>,
    ) -> usize {
        // Here the CustomModulus is a Torus and not f64 and is therefore not compatible, so
        // we cannot forward it, thankully the modulus does not impact gaussian generation success
        <(f64, f64) as RandomGenerable<Gaussian<f64>>>::single_sample_required_random_byte_count(
            distribution,
            None,
        )
    }
}
