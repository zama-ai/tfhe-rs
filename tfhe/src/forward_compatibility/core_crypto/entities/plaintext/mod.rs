use crate::core_crypto::entities::plaintext::Plaintext;
use next_tfhe::core_crypto::entities::plaintext::Plaintext as NextPlaintext;

use crate::core_crypto::commons::numeric::Numeric;

use next_tfhe::core_crypto::commons::numeric::Numeric as NextNumeric;

impl<Scalar> crate::forward_compatibility::ConvertFrom<Plaintext<Scalar>> for NextPlaintext<Scalar>
where
    Scalar: Numeric + NextNumeric,
{
    #[inline]
    fn convert_from(value: Plaintext<Scalar>) -> Self {
        let Plaintext(field_0) = value;
        Self(field_0)
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_plaintext() {
        use crate::core_crypto::entities::plaintext::Plaintext;
        use next_tfhe::core_crypto::entities::plaintext::Plaintext as NextPlaintext;

        let tfhe_struct = Plaintext(42u64);
        let _next_tfhe_struct: NextPlaintext<_> = tfhe_struct.convert_into();
    }
}
