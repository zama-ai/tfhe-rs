use crate::core_crypto::entities::plaintext_list::PlaintextList;
use next_tfhe::core_crypto::entities::plaintext_list::PlaintextList as NextPlaintextList;

use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::Container;

use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;
use next_tfhe::core_crypto::commons::traits::Container as NextContainer;

impl<Scalar, C> crate::forward_compatibility::ConvertFrom<PlaintextList<C>> for NextPlaintextList<C>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
    C: Container<Element = Scalar> + NextContainer<Element = Scalar>,
{
    #[inline]
    fn convert_from(value: PlaintextList<C>) -> Self {
        Self::from_container(value.into_container())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_plaintext_list() {
        use crate::core_crypto::entities::plaintext_list::PlaintextList;
        use next_tfhe::core_crypto::entities::plaintext_list::PlaintextList as NextPlaintextList;

        use crate::core_crypto::commons::parameters::*;

        let tfhe_struct = PlaintextList::new(0u64, PlaintextCount(10));
        let _next_tfhe_struct: NextPlaintextList<_> = tfhe_struct.convert_into();
    }
}
