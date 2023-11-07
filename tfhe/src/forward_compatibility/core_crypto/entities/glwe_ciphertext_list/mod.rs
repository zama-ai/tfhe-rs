use crate::core_crypto::entities::glwe_ciphertext_list::GlweCiphertextList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::glwe_ciphertext_list::GlweCiphertextList as NextGlweCiphertextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<GlweCiphertextList<C>>
    for NextGlweCiphertextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: GlweCiphertextList<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_glwe_ciphertext_list() {
        use crate::core_crypto::entities::glwe_ciphertext_list::GlweCiphertextList;
        use next_tfhe::core_crypto::entities::glwe_ciphertext_list::GlweCiphertextList as NextGlweCiphertextList;

        use crate::core_crypto::commons::parameters::*;

        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let glwe_ciphertext_count = GlweCiphertextCount(10);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = GlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            glwe_ciphertext_count,
            ciphertext_modulus,
        );
        let _next_tfhe_struct: NextGlweCiphertextList<_> = tfhe_struct.convert_into();
    }
}
