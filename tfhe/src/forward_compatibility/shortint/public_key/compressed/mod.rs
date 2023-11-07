use crate::forward_compatibility::ConvertInto;

use crate::shortint::public_key::compressed::CompressedPublicKey;
use next_tfhe::shortint::public_key::compressed::CompressedPublicKey as NextCompressedPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedPublicKey> for NextCompressedPublicKey {
    #[inline]
    fn convert_from(value: CompressedPublicKey) -> Self {
        let CompressedPublicKey {
            lwe_public_key,
            parameters,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            lwe_public_key.convert_into(),
            parameters.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compressed_public_key() {
        use crate::shortint::public_key::compressed::CompressedPublicKey;
        use next_tfhe::shortint::public_key::compressed::CompressedPublicKey as NextCompressedPublicKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let tfhe_struct = CompressedPublicKey::new(&cks);

        let _next_tfhe_struct: NextCompressedPublicKey = tfhe_struct.convert_into();
    }
}
