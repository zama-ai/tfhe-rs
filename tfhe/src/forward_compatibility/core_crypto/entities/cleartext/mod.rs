use crate::core_crypto::entities::cleartext::Cleartext;
use next_tfhe::core_crypto::entities::cleartext::Cleartext as NextCleartext;

use crate::core_crypto::commons::numeric::Numeric;

use next_tfhe::core_crypto::commons::numeric::Numeric as NextNumeric;

impl<Scalar> crate::forward_compatibility::ConvertFrom<Cleartext<Scalar>> for NextCleartext<Scalar>
where
    Scalar: Numeric + NextNumeric,
{
    #[inline]
    fn convert_from(value: Cleartext<Scalar>) -> Self {
        let Cleartext(field_0) = value;
        Self(field_0)
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_cleartext() {
        use crate::core_crypto::entities::cleartext::Cleartext;
        use next_tfhe::core_crypto::entities::cleartext::Cleartext as NextCleartext;

        use rand::Rng;

        let mut rng = rand::thread_rng();
        let tfhe_struct = Cleartext(rng.gen::<u64>());
        let _next_tfhe_struct: NextCleartext<_> = tfhe_struct.convert_into();
    }
}
