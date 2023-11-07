use crate::core_crypto::entities::seeded_lwe_ciphertext::SeededLweCiphertext;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_ciphertext::SeededLweCiphertext as NextSeededLweCiphertext;

use crate::core_crypto::commons::numeric::UnsignedInteger;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;

impl<Scalar> crate::forward_compatibility::ConvertFrom<SeededLweCiphertext<Scalar>>
    for NextSeededLweCiphertext<Scalar>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
{
    #[inline]
    fn convert_from(value: SeededLweCiphertext<Scalar>) -> Self {
        let lwe_size = value.lwe_size();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let scalar = value.into_scalar();

        Self::from_scalar(
            scalar,
            lwe_size.convert_into(),
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_seeded_lwe_ciphertext() {
        use crate::core_crypto::commons::math::random::CompressionSeed;
        use crate::core_crypto::commons::parameters::*;
        use crate::core_crypto::entities::seeded_lwe_ciphertext::SeededLweCiphertext;
        use crate::core_crypto::seeders::new_seeder;
        use next_tfhe::core_crypto::entities::seeded_lwe_ciphertext::SeededLweCiphertext as NextSeededLweCiphertext;

        let mut seeder = new_seeder();

        let tfhe_struct = SeededLweCiphertext::new(
            0u64,
            LweSize(101),
            CompressionSeed {
                seed: seeder.seed(),
            },
            CiphertextModulus::new_native(),
        );

        let _next_tfhe_struct: NextSeededLweCiphertext<_> = tfhe_struct.convert_into();
    }
}
