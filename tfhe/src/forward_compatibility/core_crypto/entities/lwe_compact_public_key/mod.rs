use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::lwe_compact_public_key::LweCompactPublicKey;
use next_tfhe::core_crypto::entities::lwe_compact_public_key::LweCompactPublicKey as NextLweCompactPublicKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweCompactPublicKey<C>>
    for NextLweCompactPublicKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweCompactPublicKey<C>) -> Self {
        let ciphertext_modulus = value.ciphertext_modulus();
        let container = value.into_container();

        Self::from_container(container, ciphertext_modulus.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_compact_public_key() {
        use crate::core_crypto::entities::lwe_compact_public_key::LweCompactPublicKey;
        use next_tfhe::core_crypto::entities::lwe_compact_public_key::LweCompactPublicKey as NextLweCompactPublicKey;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct =
            LweCompactPublicKey::new(0u64, LweDimension(1024), CiphertextModulus::new_native());
        let _next_tfhe_struct: NextLweCompactPublicKey<_> = tfhe_struct.convert_into();
    }
}
