use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::lwe_compact_ciphertext_list::LweCompactCiphertextList;
use next_tfhe::core_crypto::entities::lwe_compact_ciphertext_list::LweCompactCiphertextList as NextLweCompactCiphertextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweCompactCiphertextList<C>>
    for NextLweCompactCiphertextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweCompactCiphertextList<C>) -> Self {
        let lwe_size = value.lwe_size();
        let lwe_ciphertext_count = value.lwe_ciphertext_count();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            lwe_size.convert_into(),
            lwe_ciphertext_count.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_compact_ciphertext_list() {
        use crate::core_crypto::commons::parameters::*;
        use crate::core_crypto::entities::lwe_compact_ciphertext_list::LweCompactCiphertextList;
        use next_tfhe::core_crypto::entities::lwe_compact_ciphertext_list::LweCompactCiphertextList as NextLweCompactCiphertextList;

        let tfhe_struct = LweCompactCiphertextList::new(
            0u64,
            LweSize(101),
            LweCiphertextCount(10),
            CiphertextModulus::new_native(),
        );

        let _next_tfhe_struct: NextLweCompactCiphertextList<_> = tfhe_struct.convert_into();
    }
}
