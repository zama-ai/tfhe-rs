use super::*;

/// A distribution type representing uniform sampling for binary type.
#[derive(Clone, Copy)]
pub struct UniformBinary;

macro_rules! implement_uniform_binary {
    ($T:ty) => {
        impl RandomGenerable<UniformBinary> for $T {
            type CustomModulus = $T;
            #[allow(unused)]
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                distribution: UniformBinary,
            ) -> Self {
                if generator.generate_next() & 1 == 1 {
                    1
                } else {
                    0
                }
            }

            fn single_sample_success_probability(
                _distribution: UniformBinary,
                _modulus: Option<Self::CustomModulus>,
            ) -> f64 {
                // The modulus and parameters of the distribution do not impact generation success
                1.0
            }

            fn single_sample_required_random_byte_count(
                _distribution: UniformBinary,
                _modulus: Option<Self::CustomModulus>,
            ) -> usize {
                // The modulus and parameters of the distribution do not impact the amount of byte
                // required
                1
            }
        }
    };
}

implement_uniform_binary!(u8);
implement_uniform_binary!(u16);
implement_uniform_binary!(u32);
implement_uniform_binary!(u64);
implement_uniform_binary!(u128);
