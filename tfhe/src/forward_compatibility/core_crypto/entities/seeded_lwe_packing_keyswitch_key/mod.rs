use crate::core_crypto::entities::seeded_lwe_packing_keyswitch_key::SeededLwePackingKeyswitchKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_packing_keyswitch_key::SeededLwePackingKeyswitchKey as NextSeededLwePackingKeyswitchKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLwePackingKeyswitchKey<C>>
    for NextSeededLwePackingKeyswitchKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLwePackingKeyswitchKey<C>) -> Self {
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let output_glwe_size = value.output_glwe_size();
        let output_polynomial_size = value.output_polynomial_size();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            output_glwe_size.convert_into(),
            output_polynomial_size.convert_into(),
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_seeded_lwe_packing_keyswitch_key() {
        use crate::core_crypto::entities::seeded_lwe_packing_keyswitch_key::SeededLwePackingKeyswitchKey;
        use next_tfhe::core_crypto::entities::seeded_lwe_packing_keyswitch_key::SeededLwePackingKeyswitchKey as NextSeededLwePackingKeyswitchKey;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let decomp_base_log = DecompositionBaseLog(23);
        let decomp_level_count = DecompositionLevelCount(1);
        let input_key_lwe_dimension = LweDimension(100);
        let output_key_glwe_dimension = GlweDimension(2);
        let output_key_polynomial_size = PolynomialSize(2048);
        let compression_seed = Seed(42).into();
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = SeededLwePackingKeyswitchKey::new(
            0u64,
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension,
            output_key_glwe_dimension,
            output_key_polynomial_size,
            compression_seed,
            ciphertext_modulus,
        );
        let _next_tfhe_struct: NextSeededLwePackingKeyswitchKey<_> = tfhe_struct.convert_into();
    }
}
