use crate::forward_compatibility::ConvertInto;

use crate::core_crypto::entities::glwe_secret_key::GlweSecretKey;
use next_tfhe::core_crypto::entities::glwe_secret_key::GlweSecretKey as NextGlweSecretKey;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<GlweSecretKey<C>> for NextGlweSecretKey<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: GlweSecretKey<C>) -> Self {
        let polynomial_size = value.polynomial_size();
        let container = value.into_container();

        Self::from_container(container, polynomial_size.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_glwe_secret_key() {
        use crate::core_crypto::entities::glwe_secret_key::GlweSecretKey;
        use next_tfhe::core_crypto::entities::glwe_secret_key::GlweSecretKey as NextGlweSecretKey;

        use crate::core_crypto::commons::parameters::*;

        let polynomial_size = PolynomialSize(2048);
        let glwe_dimension = GlweDimension(1);

        let tfhe_struct = GlweSecretKey::new_empty_key(0u64, glwe_dimension, polynomial_size);
        let _next_tfhe_struct: NextGlweSecretKey<_> = tfhe_struct.convert_into();
    }
}
