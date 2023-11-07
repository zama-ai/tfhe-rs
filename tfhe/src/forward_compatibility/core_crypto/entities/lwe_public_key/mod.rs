use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::lwe_public_key::LwePublicKey;
use next_tfhe::core_crypto::entities::lwe_public_key::LwePublicKey as NextLwePublicKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LwePublicKey<C>> for NextLwePublicKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LwePublicKey<C>) -> Self {
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
    fn test_conversion_lwe_public_key() {
        use crate::core_crypto::entities::lwe_public_key::LwePublicKey;
        use next_tfhe::core_crypto::entities::lwe_public_key::LwePublicKey as NextLwePublicKey;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = LwePublicKey::new(
            0u64,
            LweSize(101),
            LwePublicKeyZeroEncryptionCount(10),
            CiphertextModulus::new_native(),
        );
        let _next_tfhe_struct: NextLwePublicKey<_> = tfhe_struct.convert_into();
    }
}
