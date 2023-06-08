use super::*;
use crate::core_crypto::commons::numeric::Numeric;

/// A distribution type that samples a uniform value with probability `1 - prob_zero`, and a zero
/// value with probaibility `prob_zero`.
#[derive(Copy, Clone)]
pub struct UniformWithZeros {
    /// The probability of the output being a zero
    pub prob_zero: f32,
}

macro_rules! implement_uniform_with_zeros {
    ($T:ty, $bits:literal) => {
        impl RandomGenerable<UniformWithZeros> for $T {
            type CustomModulus = $T;
            #[allow(unused)]
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                UniformWithZeros { prob_zero }: UniformWithZeros,
            ) -> Self {
                let uniform_u32: u32 = u32::generate_one(generator, Uniform);
                let float_sample = uniform_u32 as f32 / u32::MAX as f32;
                if float_sample < prob_zero {
                    <$T>::ZERO
                } else {
                    Self::generate_one(generator, Uniform)
                }
            }
        }
    };
}

implement_uniform_with_zeros!(u8, 1);
implement_uniform_with_zeros!(u16, 2);
implement_uniform_with_zeros!(u32, 4);
implement_uniform_with_zeros!(u64, 8);
implement_uniform_with_zeros!(u128, 16);
implement_uniform_with_zeros!(i8, 1);
implement_uniform_with_zeros!(i16, 2);
implement_uniform_with_zeros!(i32, 4);
implement_uniform_with_zeros!(i64, 8);
implement_uniform_with_zeros!(i128, 16);
