use crate::core_crypto::entities::seeded_glwe_ciphertext_list::SeededGlweCiphertextList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_glwe_ciphertext_list::SeededGlweCiphertextList as NextSeededGlweCiphertextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededGlweCiphertextList<C>>
    for NextSeededGlweCiphertextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededGlweCiphertextList<C>) -> Self {
        let glwe_size = value.glwe_size();
        let polynomial_size = value.polynomial_size();
        let compression_seed = value.compression_seed();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            glwe_size.convert_into(),
            polynomial_size.convert_into(),
            compression_seed.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;
    #[test]
    fn test_conversion_seeded_glwe_ciphertext_list() {
        use crate::core_crypto::entities::seeded_glwe_ciphertext_list::SeededGlweCiphertextList;
        use next_tfhe::core_crypto::entities::seeded_glwe_ciphertext_list::SeededGlweCiphertextList as NextSeededGlweCiphertextList;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let glwe_size = GlweSize(2);
        let polynomial_size = PolynomialSize(2048);
        let ciphertext_count = GlweCiphertextCount(10);
        let compression_seed = Seed(42).into();
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = SeededGlweCiphertextList::new(
            0u64,
            glwe_size,
            polynomial_size,
            ciphertext_count,
            compression_seed,
            ciphertext_modulus,
        );

        let _next_tfhe_struct: NextSeededGlweCiphertextList<_> = tfhe_struct.convert_into();
    }
}
