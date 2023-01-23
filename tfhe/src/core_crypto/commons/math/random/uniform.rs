use super::*;

/// A distribution type representing uniform sampling for unsigned integer types. The value is
/// uniformly sampled in `[0, 2^n[` where `n` is the size of the integer type.
#[derive(Copy, Clone)]
pub struct Uniform;

macro_rules! implement_uniform {
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

implement_uniform!(u8);
implement_uniform!(u16);
implement_uniform!(u32);
implement_uniform!(u64);
implement_uniform!(u128);
implement_uniform!(i8);
implement_uniform!(i16);
implement_uniform!(i32);
implement_uniform!(i64);
implement_uniform!(i128);
