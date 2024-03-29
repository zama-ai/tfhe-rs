use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::ggsw_ciphertext::GgswCiphertext;
use next_tfhe::core_crypto::entities::ggsw_ciphertext::GgswCiphertext as NextGgswCiphertext;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<GgswCiphertext<C>>
    for NextGgswCiphertext<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: GgswCiphertext<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let decomp_base_log = value.decomposition_base_log();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            decomp_base_log.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_ggsw_ciphertext() {
        use crate::core_crypto::commons::parameters::*;
        use crate::core_crypto::entities::ggsw_ciphertext::GgswCiphertext;
        use next_tfhe::core_crypto::entities::ggsw_ciphertext::GgswCiphertext as NextGgswCiphertext;

        let glwe_size = GlweSize(2);
        let polynomial_size = PolynomialSize(2048);
        let decomp_base_log = DecompositionBaseLog(23);
        let container = vec![0u64; glwe_size.0 * glwe_size.0 * polynomial_size.0];
        let ciphertext_modulus = CiphertextModulus::new_native();
        let tfhe_struct = GgswCiphertext::from_container(
            container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        );

        let _next_tfhe_struct: NextGgswCiphertext<_> = tfhe_struct.convert_into();
    }
}
