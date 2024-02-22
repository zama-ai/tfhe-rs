use super::*;
use crate::core_crypto::commons::math::torus::{FromTorus, UnsignedTorus};
use crate::core_crypto::commons::numeric::{CastInto, Numeric};

/// A distribution type representing random sampling of floating point numbers, following a
/// gaussian distribution.
#[derive(Clone, Copy)]
pub struct Gaussian<T: FloatingPoint> {
    /// The standard deviation of the distribution.
    pub std: T,
    /// The mean of the distribution.
    pub mean: T,
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

            fn required_bytes_for_safe_generation(_distribution: Gaussian<$T>) -> usize {
                // We use $T to sample the noise, and we need 4/pi inputs to generate such an output
                // (here we take 32 to keep a safety margin).
                <$T>::BITS as usize / 8 * 32
            }
        }
    };
}

implement_gaussian!(f32, i32);
implement_gaussian!(f64, i64);

impl<Torus> RandomGenerable<Gaussian<f64>> for (Torus, Torus)
where
    Torus: UnsignedTorus,
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

    fn required_bytes_for_safe_generation(distribution: Gaussian<f64>) -> usize {
        <(f64, f64)>::required_bytes_for_safe_generation(distribution)
    }

    fn required_bytes_for_safe_generation_custom_mod(
        distribution: Gaussian<f64>,
        _custom_modulus: Self::CustomModulus,
    ) -> usize {
        // The gaussian does not need to know the custom modulus for safe generation as it's only
        // scaling a gaussian sample directly
        Self::required_bytes_for_safe_generation(distribution)
    }
}

impl<Torus> RandomGenerable<Gaussian<f64>> for Torus
where
    Torus: UnsignedTorus,
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

    fn required_bytes_for_safe_generation(distribution: Gaussian<f64>) -> usize {
        <(f64, f64)>::required_bytes_for_safe_generation(distribution)
    }

    fn required_bytes_for_safe_generation_custom_mod(
        distribution: Gaussian<f64>,
        _custom_modulus: Self::CustomModulus,
    ) -> usize {
        // The gaussian does not need to know the custom modulus for safe generation as it's only
        // scaling a gaussian sample directly
        Self::required_bytes_for_safe_generation(distribution)
    }
}
