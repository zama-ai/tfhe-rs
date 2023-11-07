use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKey;
use next_tfhe::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKey as NextSeededLweKeyswitchKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLweKeyswitchKey<C>>
    for NextSeededLweKeyswitchKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLweKeyswitchKey<C>) -> Self {
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let output_lwe_size = value.output_lwe_size();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            output_lwe_size.convert_into(),
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_seeded_lwe_keyswitch_key() {
        use crate::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKey;
        use next_tfhe::core_crypto::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKey as NextSeededLweKeyswitchKey;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = SeededLweKeyswitchKey::new(
            0u64,
            DecompositionBaseLog(5),
            DecompositionLevelCount(3),
            LweDimension(200),
            LweDimension(100),
            Seed(42).into(),
            CiphertextModulus::new_native(),
        );

        let _next_tfhe_struct: NextSeededLweKeyswitchKey<_> = tfhe_struct.convert_into();
    }
}
