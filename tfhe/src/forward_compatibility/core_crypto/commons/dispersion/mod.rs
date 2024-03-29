use crate::core_crypto::commons::dispersion::StandardDev;
use next_tfhe::core_crypto::commons::dispersion::StandardDev as NextStandardDev;

impl crate::forward_compatibility::ConvertFrom<StandardDev> for NextStandardDev {
    #[inline]
    fn convert_from(value: StandardDev) -> Self {
        let StandardDev(field_0) = value;
        Self(field_0)
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;
    #[test]
    fn test_conversion_standard_dev() {
        use crate::core_crypto::commons::dispersion::StandardDev;
        use next_tfhe::core_crypto::commons::dispersion::StandardDev as NextStandardDev;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = StandardDev(rng.gen());
        let _next_tfhe_struct: NextStandardDev = tfhe_struct.convert_into();
    }
}
