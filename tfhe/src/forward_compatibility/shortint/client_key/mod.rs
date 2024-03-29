use crate::forward_compatibility::ConvertInto;

use crate::shortint::client_key::ClientKey;
use next_tfhe::shortint::client_key::ClientKey as NextClientKey;

impl crate::forward_compatibility::ConvertFrom<ClientKey> for NextClientKey {
    #[inline]
    fn convert_from(value: ClientKey) -> Self {
        let ClientKey {
            glwe_secret_key,
            lwe_secret_key,
            parameters,
        } = value;

        Self::from_raw_parts(
            glwe_secret_key.convert_into(),
            lwe_secret_key.convert_into(),
            parameters.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_client_key() {
        use crate::shortint::client_key::ClientKey;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use next_tfhe::shortint::client_key::ClientKey as NextClientKey;

        let tfhe_struct = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let _next_tfhe_struct: NextClientKey = tfhe_struct.convert_into();
    }
}
