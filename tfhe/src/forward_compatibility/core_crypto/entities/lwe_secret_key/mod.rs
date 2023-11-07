use crate::core_crypto::entities::lwe_secret_key::LweSecretKey;

use next_tfhe::core_crypto::entities::lwe_secret_key::LweSecretKey as NextLweSecretKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<LweSecretKey<C>> for NextLweSecretKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: LweSecretKey<C>) -> Self {
        let container = value.into_container();

        Self::from_container(container)
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_lwe_secret_key() {
        use crate::core_crypto::entities::lwe_secret_key::LweSecretKey;
        use next_tfhe::core_crypto::entities::lwe_secret_key::LweSecretKey as NextLweSecretKey;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = LweSecretKey::new_empty_key(0u64, LweDimension(100));
        let _next_tfhe_struct: NextLweSecretKey<_> = tfhe_struct.convert_into();
    }
}
