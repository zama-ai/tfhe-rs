use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::numeric::UnsignedInteger;

use next_tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus as NextCiphertextModulus;
use next_tfhe::core_crypto::commons::numeric::UnsignedInteger as NextUnsignedInteger;

impl<Scalar> crate::forward_compatibility::ConvertFrom<CiphertextModulus<Scalar>>
    for NextCiphertextModulus<Scalar>
where
    Scalar: UnsignedInteger + NextUnsignedInteger,
{
    #[inline]
    fn convert_from(value: CiphertextModulus<Scalar>) -> Self {
        if value.is_native_modulus() {
            Self::new_native()
        } else {
            Self::new(value.get_custom_modulus())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_ciphertext_modulus() {
        use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
        use next_tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulus as NextCiphertextModulus;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CiphertextModulus::new(0);
        let _next_tfhe_struct: NextCiphertextModulus<u64> = tfhe_struct.convert_into();

        let tfhe_struct = CiphertextModulus::new(rng.gen_range(0..=(1 << 64)));
        let _next_tfhe_struct: NextCiphertextModulus<u64> = tfhe_struct.convert_into();
    }
}
