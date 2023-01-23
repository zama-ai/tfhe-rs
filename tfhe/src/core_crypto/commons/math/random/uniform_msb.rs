use super::*;
use crate::core_crypto::commons::numeric::Numeric;

/// A distribution type representing random sampling for unsigned integer types, where the `n`
/// most significant bits are sampled randomly in `[0, 2^n[`.
#[derive(Copy, Clone)]
pub struct UniformMsb {
    /// The number of most significant bits that must be randomly set.
    pub n: usize,
}

macro_rules! implement_uniform_some_msb {
    ($T:ty) => {
        impl RandomGenerable<UniformMsb> for $T {
            type CustomModulus = $T;
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                UniformMsb { n }: UniformMsb,
            ) -> Self {
                <$T>::generate_one(generator, Uniform) << (<$T as Numeric>::BITS - n)
            }
        }
    };
}

implement_uniform_some_msb!(u8);
implement_uniform_some_msb!(u16);
implement_uniform_some_msb!(u32);
implement_uniform_some_msb!(u64);
implement_uniform_some_msb!(u128);
