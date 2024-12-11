use super::*;

/// A distribution type representing uniform sampling for ternary type.
#[derive(Clone, Copy)]
pub struct UniformTernary;

macro_rules! implement_uniform_ternary {
    ($T:ty) => {
        impl RandomGenerable<UniformTernary> for $T {
            type CustomModulus = $T;
            #[allow(unused)]
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                distribution: UniformTernary,
            ) -> Self {
                loop {
                    match generator.generate_next() & 3 {
                        0 => return 0,
                        1 => return 1,
                        2 => return (0 as $T).wrapping_sub(1),
                        _ => {}
                    }
                }
            }

            fn single_sample_success_probability(
                _distribution: UniformTernary,
                _modulus: Option<Self::CustomModulus>,
            ) -> f64 {
                // The modulus and parameters of the distribution do not impact generation success
                1.0
            }

            fn single_sample_required_random_byte_count(
                _distribution: UniformTernary,
                _modulus: Option<Self::CustomModulus>,
            ) -> usize {
                // The modulus and parameters of the distribution do not impact the amount of byte
                // required
                1
            }
        }
    };
}

implement_uniform_ternary!(u8);
implement_uniform_ternary!(u16);
implement_uniform_ternary!(u32);
implement_uniform_ternary!(u64);
implement_uniform_ternary!(u128);
