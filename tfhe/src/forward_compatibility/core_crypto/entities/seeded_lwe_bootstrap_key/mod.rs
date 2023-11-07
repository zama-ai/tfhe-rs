use crate::core_crypto::entities::seeded_lwe_bootstrap_key::SeededLweBootstrapKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_bootstrap_key::SeededLweBootstrapKey as NextSeededLweBootstrapKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLweBootstrapKey<C>>
    for NextSeededLweBootstrapKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLweBootstrapKey<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_seeded_lwe_bootstrap_key() {
        use crate::core_crypto::entities::seeded_lwe_bootstrap_key::SeededLweBootstrapKey;
        use next_tfhe::core_crypto::entities::seeded_lwe_bootstrap_key::SeededLweBootstrapKey as NextSeededLweBootstrapKey;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = SeededLweBootstrapKey::new(
            0u64,
            GlweSize(2),
            PolynomialSize(2048),
            DecompositionBaseLog(23),
            DecompositionLevelCount(1),
            LweDimension(100),
            Seed(42).into(),
            CiphertextModulus::new_native(),
        );

        let _next_tfhe_struct: NextSeededLweBootstrapKey<_> = tfhe_struct.convert_into();
    }
}
