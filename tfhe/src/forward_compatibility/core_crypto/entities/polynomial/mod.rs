use crate::core_crypto::entities::polynomial::Polynomial;

use next_tfhe::core_crypto::entities::polynomial::Polynomial as NextPolynomial;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<Polynomial<C>> for NextPolynomial<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: Polynomial<C>) -> Self {
        Self::from_container(value.into_container())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_polynomial() {
        use crate::core_crypto::entities::polynomial::Polynomial;
        use next_tfhe::core_crypto::entities::polynomial::Polynomial as NextPolynomial;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = Polynomial::new(0u64, PolynomialSize(2048));
        let _next_tfhe_struct: NextPolynomial<_> = tfhe_struct.convert_into();
    }
}
