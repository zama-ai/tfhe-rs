use super::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;

/// A distribution type representing uniform sampling for unsigned integer types. The value is
/// uniformly sampled in `[0, 2^n[` where `n` is the size of the integer type.
#[derive(Copy, Clone)]
pub struct Uniform;

macro_rules! implement_uniform_uint {
    ($T:ty) => {
        impl RandomGenerable<Uniform> for $T {
            type CustomModulus = $T;
            #[allow(unused)]
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                distribution: Uniform,
            ) -> Self {
                let mut buf = [0; std::mem::size_of::<$T>()];
                buf.iter_mut().for_each(|a| *a = generator.generate_next());
                // We use from_le_bytes as most platforms are low endian, this avoids endianness
                // issues
                <$T>::from_le_bytes(buf)
            }

            #[allow(unused)]
            fn generate_one_custom_modulus<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                distribution: Uniform,
                custom_modulus: Self::CustomModulus,
            ) -> Self {
                let mut buf = [0; std::mem::size_of::<$T>()];

                let modulus_bits = custom_modulus.ceil_ilog2();
                let mod_mask = <$T>::MAX >> (<$T>::BITS - modulus_bits);

                loop {
                    buf.iter_mut().for_each(|a| *a = generator.generate_next());
                    // We use from_le_bytes as most platforms are low endian, this avoids endianness
                    // issues
                    let native_int_random = <$T>::from_le_bytes(buf);
                    let candidate_for_random = native_int_random & mod_mask;
                    if candidate_for_random < custom_modulus {
                        break candidate_for_random;
                    }
                }
            }
        }
    };
}

implement_uniform_uint!(u8);
implement_uniform_uint!(u16);
implement_uniform_uint!(u32);
implement_uniform_uint!(u64);
implement_uniform_uint!(u128);

// TODO: for now we don't need and don't support custom moduli for the generation of signed integers
macro_rules! implement_uniform_int {
    ($T:ty) => {
        impl RandomGenerable<Uniform> for $T {
            type CustomModulus = $T;
            #[allow(unused)]
            fn generate_one<G: ByteRandomGenerator>(
                generator: &mut RandomGenerator<G>,
                distribution: Uniform,
            ) -> Self {
                let mut buf = [0; std::mem::size_of::<$T>()];
                buf.iter_mut().for_each(|a| *a = generator.generate_next());
                // We use from_le_bytes as most platforms are low endian, this avoids endianness
                // issues
                <$T>::from_le_bytes(buf)
            }
        }
    };
}

implement_uniform_int!(i8);
implement_uniform_int!(i16);
implement_uniform_int!(i32);
implement_uniform_int!(i64);
implement_uniform_int!(i128);
