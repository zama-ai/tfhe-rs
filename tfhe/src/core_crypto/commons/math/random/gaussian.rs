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
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                Gaussian { std, mean }: Gaussian<$T>,
            ) -> Self {
                let output: ($T, $T);
                let mut uniform_rand = vec![0 as $S; 2];
                loop {
                    let n_bytes = (<$S as Numeric>::BITS * 2) / 8;
                    let uniform_rand_bytes = unsafe {
                        std::slice::from_raw_parts_mut(
                            uniform_rand.as_mut_ptr() as *mut u8,
                            n_bytes,
                        )
                    };
                    uniform_rand_bytes
                        .iter_mut()
                        .for_each(|a| *a = generator.generate_next());
                    let size = <$T>::BITS as i32;
                    let mut u: $T = uniform_rand[0].cast_into();
                    u *= <$T>::TWO.powi(-size + 1);
                    let mut v: $T = uniform_rand[1].cast_into();
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
        }
    };
}

implement_gaussian!(f32, i32);
implement_gaussian!(f64, i64);

impl<Torus> RandomGenerable<Gaussian<f64>> for (Torus, Torus)
where
    Torus: UnsignedTorus,
{
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
}

impl<Torus> RandomGenerable<Gaussian<f64>> for Torus
where
    Torus: UnsignedTorus,
{
    fn generate_one<G: ByteRandomGenerator>(
        generator: &mut RandomGenerator<G>,
        distribution: Gaussian<f64>,
    ) -> Self {
        let (s1, _) = <(f64, f64)>::generate_one(generator, distribution);
        <Torus as FromTorus<f64>>::from_torus(s1)
    }
}
