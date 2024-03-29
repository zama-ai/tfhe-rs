use crate::forward_compatibility::ConvertInto;

use crate::boolean::public_key::CompressedPublicKey;
use next_tfhe::boolean::public_key::CompressedPublicKey as NextCompressedPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedPublicKey> for NextCompressedPublicKey {
    #[inline]
    fn convert_from(value: CompressedPublicKey) -> Self {
        let CompressedPublicKey {
            compressed_lwe_public_key,
            parameters,
        } = value;

        Self::from_raw_parts(
            compressed_lwe_public_key.convert_into(),
            parameters.convert_into(),
        )
    }
}

use crate::boolean::public_key::PublicKey;
use next_tfhe::boolean::public_key::PublicKey as NextPublicKey;

impl crate::forward_compatibility::ConvertFrom<PublicKey> for NextPublicKey {
    #[inline]
    fn convert_from(value: PublicKey) -> Self {
        let PublicKey {
            lwe_public_key,
            parameters,
        } = value;

        Self::from_raw_parts(lwe_public_key.convert_into(), parameters.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compressed_public_key() {
        use crate::boolean::public_key::CompressedPublicKey;
        use next_tfhe::boolean::public_key::CompressedPublicKey as NextCompressedPublicKey;

        use crate::boolean::client_key::ClientKey;
        use crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS;

        let cks = ClientKey::new(&DEFAULT_PARAMETERS_KS_PBS);
        let tfhe_struct = CompressedPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_public_key() {
        use crate::boolean::public_key::PublicKey;
        use next_tfhe::boolean::public_key::PublicKey as NextPublicKey;

        use crate::boolean::client_key::ClientKey;
        use crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS;

        let cks = ClientKey::new(&DEFAULT_PARAMETERS_KS_PBS);
        let tfhe_struct = PublicKey::new(&cks);
        let _next_tfhe_struct: NextPublicKey = tfhe_struct.convert_into();
    }
}
