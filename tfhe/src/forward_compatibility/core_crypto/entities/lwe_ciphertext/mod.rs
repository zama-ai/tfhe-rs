use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::lwe_ciphertext::LweCiphertext;
use next_tfhe::core_crypto::entities::lwe_ciphertext::LweCiphertext as NextLweCiphertext;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweCiphertext<C>> for NextLweCiphertext<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweCiphertext<C>) -> Self {
        let ciphertext_modulus = value.ciphertext_modulus();
        let data = value.into_container();
        Self::from_container(data, ciphertext_modulus.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_ciphertext() {
        use crate::core_crypto::entities::lwe_ciphertext::LweCiphertext;
        use next_tfhe::core_crypto::entities::lwe_ciphertext::LweCiphertext as NextLweCiphertext;

        use crate::core_crypto::commons::parameters::*;

        let lwe_size = LweSize(101);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let tfhe_struct = LweCiphertext::new(0u64, lwe_size, ciphertext_modulus);
        let _next_tfhe_struct: NextLweCiphertext<_> = tfhe_struct.convert_into();
    }
}
