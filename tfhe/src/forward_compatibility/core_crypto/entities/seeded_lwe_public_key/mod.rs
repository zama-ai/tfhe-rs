use crate::core_crypto::entities::seeded_lwe_public_key::SeededLwePublicKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_public_key::SeededLwePublicKey as NextSeededLwePublicKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLwePublicKey<C>>
    for NextSeededLwePublicKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLwePublicKey<C>) -> Self {
        let lwe_size = value.lwe_size();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
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
    fn test_conversion_seeded_lwe_public_key() {
        use crate::core_crypto::entities::seeded_lwe_public_key::SeededLwePublicKey;
        use next_tfhe::core_crypto::entities::seeded_lwe_public_key::SeededLwePublicKey as NextSeededLwePublicKey;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = SeededLwePublicKey::new(
            0u64,
            LweSize(101),
            LwePublicKeyZeroEncryptionCount(10),
            Seed(42).into(),
            CiphertextModulus::new_native(),
        );
        let _next_tfhe_struct: NextSeededLwePublicKey<_> = tfhe_struct.convert_into();
    }
}
