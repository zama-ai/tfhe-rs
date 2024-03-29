use crate::core_crypto::entities::seeded_lwe_compact_public_key::SeededLweCompactPublicKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_compact_public_key::SeededLweCompactPublicKey as NextSeededLweCompactPublicKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLweCompactPublicKey<C>>
    for NextSeededLweCompactPublicKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLweCompactPublicKey<C>) -> Self {
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_seeded_lwe_compact_public_key() {
        use crate::core_crypto::entities::seeded_lwe_compact_public_key::SeededLweCompactPublicKey;
        use next_tfhe::core_crypto::entities::seeded_lwe_compact_public_key::SeededLweCompactPublicKey as NextSeededLweCompactPublicKey;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let lwe_dimension = LweDimension(1024);
        let compression_seed = Seed(42).into();
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = SeededLweCompactPublicKey::new(
            0u64,
            lwe_dimension,
            compression_seed,
            ciphertext_modulus,
        );

        let _next_tfhe_struct: NextSeededLweCompactPublicKey<_> = tfhe_struct.convert_into();
    }
}
