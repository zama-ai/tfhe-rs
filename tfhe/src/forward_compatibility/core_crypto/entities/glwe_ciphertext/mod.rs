use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

use crate::core_crypto::entities::glwe_ciphertext::GlweCiphertext;
use next_tfhe::core_crypto::entities::glwe_ciphertext::GlweCiphertext as NextGlweCiphertext;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<GlweCiphertext<C>>
    for NextGlweCiphertext<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: GlweCiphertext<C>) -> Self {
        let polynomial_size = value.polynomial_size();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            polynomial_size.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_glwe_ciphertext() {
        use crate::core_crypto::entities::glwe_ciphertext::GlweCiphertext;
        use next_tfhe::core_crypto::entities::glwe_ciphertext::GlweCiphertext as NextGlweCiphertext;

        use crate::core_crypto::commons::parameters::*;

        let polynomial_size = PolynomialSize(2048);
        let glwe_size = GlweSize(2);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
        let _next_tfhe_struct: NextGlweCiphertext<_> = tfhe_struct.convert_into();
    }
}
