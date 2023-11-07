use crate::core_crypto::entities::polynomial_list::PolynomialList;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::core_crypto::entities::polynomial_list::PolynomialList as NextPolynomialList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<PolynomialList<C>>
    for NextPolynomialList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: PolynomialList<C>) -> Self {
        let polynomial_size = value.polynomial_size();
        let container = value.into_container();

        Self::from_container(container, polynomial_size.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_polynomial_list() {
        use crate::core_crypto::entities::polynomial_list::PolynomialList;
        use next_tfhe::core_crypto::entities::polynomial_list::PolynomialList as NextPolynomialList;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = PolynomialList::new(0u64, PolynomialSize(2048), PolynomialCount(10));
        let _next_tfhe_struct: NextPolynomialList<_> = tfhe_struct.convert_into();
    }
}
