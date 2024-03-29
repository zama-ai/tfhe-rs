use crate::forward_compatibility::ConvertInto;

use crate::shortint::public_key::standard::PublicKey;
use next_tfhe::shortint::public_key::standard::PublicKey as NextPublicKey;

impl crate::forward_compatibility::ConvertFrom<PublicKey> for NextPublicKey {
    #[inline]
    fn convert_from(value: PublicKey) -> Self {
        let PublicKey {
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
    fn test_conversion_public_key() {
        use crate::shortint::public_key::standard::PublicKey;
        use next_tfhe::shortint::public_key::standard::PublicKey as NextPublicKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let tfhe_struct = PublicKey::new(&cks);

        let _next_tfhe_struct: NextPublicKey = tfhe_struct.convert_into();
    }
}
