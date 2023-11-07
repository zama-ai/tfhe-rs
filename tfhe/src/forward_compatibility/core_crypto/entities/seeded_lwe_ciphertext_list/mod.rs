use crate::core_crypto::entities::seeded_lwe_ciphertext_list::SeededLweCiphertextList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::seeded_lwe_ciphertext_list::SeededLweCiphertextList as NextSeededLweCiphertextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<SeededLweCiphertextList<C>>
    for NextSeededLweCiphertextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: SeededLweCiphertextList<C>) -> Self {
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
    fn test_conversion_seeded_lwe_ciphertext_list() {
        use crate::core_crypto::entities::seeded_lwe_ciphertext_list::SeededLweCiphertextList;
        use next_tfhe::core_crypto::entities::seeded_lwe_ciphertext_list::SeededLweCiphertextList as NextSeededLweCiphertextList;

        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::commons::parameters::*;

        let lwe_size = LweSize(101);
        let ciphertext_count = LweCiphertextCount(10);
        let compression_seed = Seed(42).into();
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = SeededLweCiphertextList::new(
            0u64,
            lwe_size,
            ciphertext_count,
            compression_seed,
            ciphertext_modulus,
        );

        let _next_tfhe_struct: NextSeededLweCiphertextList<_> = tfhe_struct.convert_into();
    }
}
