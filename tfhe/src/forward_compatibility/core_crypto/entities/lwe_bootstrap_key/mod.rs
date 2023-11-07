use crate::core_crypto::entities::lwe_bootstrap_key::LweBootstrapKey;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::lwe_bootstrap_key::LweBootstrapKey as NextLweBootstrapKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweBootstrapKey<C>>
    for NextLweBootstrapKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweBootstrapKey<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomp_base_log = value.decomposition_base_log();
        let decomp_level_count = value.decomposition_level_count();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            decomp_base_log.convert_into(),
            decomp_level_count.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_bootstrap_key() {
        use crate::core_crypto::entities::lwe_bootstrap_key::LweBootstrapKey;
        use next_tfhe::core_crypto::entities::lwe_bootstrap_key::LweBootstrapKey as NextLweBootstrapKey;

        use crate::core_crypto::commons::parameters::*;

        let input_lwe_dimension = LweDimension(100);
        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let decomp_base_log = DecompositionBaseLog(23);
        let decomp_level_count = DecompositionLevelCount(1);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = LweBootstrapKey::new(
            0u64,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            ciphertext_modulus,
        );
        let _next_tfhe_struct: NextLweBootstrapKey<_> = tfhe_struct.convert_into();
    }
}
