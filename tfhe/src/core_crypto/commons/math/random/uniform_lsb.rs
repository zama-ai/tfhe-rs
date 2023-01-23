use super::*;
use crate::core_crypto::commons::numeric::Numeric;
/// A distribution type representing random sampling for unsigned integer type, where the `n`
/// least significant bits are sampled in `[0, 2^n[`.
#[derive(Copy, Clone)]
pub struct UniformLsb {
    /// The number of least significant bits that should be set randomly.
    pub n: usize,
}

macro_rules! implement_uniform_some_lsb {
    ($T:ty) => {
        impl RandomGenerable<UniformLsb> for $T {
            type CustomModulus = $T;
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                UniformLsb { n }: UniformLsb,
            ) -> Self {
                <$T>::generate_one(generator, Uniform) >> (<$T as Numeric>::BITS - n)
            }
        }
    };
}

implement_uniform_some_lsb!(u8);
implement_uniform_some_lsb!(u16);
implement_uniform_some_lsb!(u32);
implement_uniform_some_lsb!(u64);
implement_uniform_some_lsb!(u128);
