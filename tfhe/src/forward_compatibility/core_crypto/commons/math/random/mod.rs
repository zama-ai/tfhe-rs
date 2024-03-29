use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::commons::math::random::Seed;
use next_tfhe::core_crypto::commons::math::random::Seed as NextSeed;

impl crate::forward_compatibility::ConvertFrom<Seed> for NextSeed {
    #[inline]
    fn convert_from(value: Seed) -> Self {
        let Seed(seed) = value;
        Self(seed)
    }
}

use crate::core_crypto::commons::math::random::CompressionSeed;
use next_tfhe::core_crypto::commons::math::random::CompressionSeed as NextCompressionSeed;

impl crate::forward_compatibility::ConvertFrom<CompressionSeed> for NextCompressionSeed {
    #[inline]
    fn convert_from(value: CompressionSeed) -> Self {
        let CompressionSeed { seed } = value;
        Self {
            seed: seed.convert_into(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compression_seed() {
        use crate::core_crypto::commons::math::random::{CompressionSeed, Seed};
        use next_tfhe::core_crypto::commons::math::random::CompressionSeed as NextCompressionSeed;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CompressionSeed {
            seed: Seed(rng.gen()),
        };
        let _next_tfhe_struct: NextCompressionSeed = tfhe_struct.convert_into();
    }
}
