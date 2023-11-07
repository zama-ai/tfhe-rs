use crate::forward_compatibility::ConvertInto;

use crate::boolean::client_key::ClientKey;
use next_tfhe::boolean::client_key::ClientKey as NextClientKey;

impl crate::forward_compatibility::ConvertFrom<ClientKey> for NextClientKey {
    #[inline]
    fn convert_from(value: ClientKey) -> Self {
        let (lwe_secret_key, glwe_secret_key, parameters) = value.into_raw_parts();

        Self::new_from_raw_parts(
            lwe_secret_key.convert_into(),
            glwe_secret_key.convert_into(),
            parameters.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_client_key() {
        use crate::boolean::client_key::ClientKey;
        use next_tfhe::boolean::client_key::ClientKey as NextClientKey;

        use crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS;

        let tfhe_struct = ClientKey::new(&DEFAULT_PARAMETERS_KS_PBS);
        let _next_tfhe_struct: NextClientKey = tfhe_struct.convert_into();
    }
}
