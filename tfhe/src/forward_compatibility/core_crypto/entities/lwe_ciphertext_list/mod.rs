use crate::core_crypto::entities::lwe_ciphertext_list::LweCiphertextList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::lwe_ciphertext_list::LweCiphertextList as NextLweCiphertextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweCiphertextList<C>>
    for NextLweCiphertextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweCiphertextList<C>) -> Self {
        let lwe_size = value.lwe_size();
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(
            container,
            lwe_size.convert_into(),
            ciphertext_modulus.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_ciphertext_list() {
        use crate::core_crypto::entities::lwe_ciphertext_list::LweCiphertextList;
        use next_tfhe::core_crypto::entities::lwe_ciphertext_list::LweCiphertextList as NextLweCiphertextList;

        use crate::core_crypto::commons::parameters::*;

        let lwe_size = LweSize(101);
        let lwe_ciphertext_count = LweCiphertextCount(10);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct =
            LweCiphertextList::new(0u64, lwe_size, lwe_ciphertext_count, ciphertext_modulus);
        let _next_tfhe_struct: NextLweCiphertextList<_> = tfhe_struct.convert_into();
    }
}
