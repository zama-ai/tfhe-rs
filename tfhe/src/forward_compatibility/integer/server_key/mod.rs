use crate::forward_compatibility::ConvertInto;

use crate::integer::server_key::ServerKey;
use next_tfhe::integer::server_key::ServerKey as NextServerKey;

impl crate::forward_compatibility::ConvertFrom<ServerKey> for NextServerKey {
    #[inline]
    fn convert_from(value: ServerKey) -> Self {
        let ServerKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

use crate::integer::server_key::CompressedServerKey;
use next_tfhe::integer::server_key::CompressedServerKey as NextCompressedServerKey;

impl crate::forward_compatibility::ConvertFrom<CompressedServerKey> for NextCompressedServerKey {
    #[inline]
    fn convert_from(value: CompressedServerKey) -> Self {
        let CompressedServerKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_server_key() {
        use next_tfhe::integer::server_key::ServerKey as NextServerKey;

        use crate::integer::gen_keys_radix;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (_cks, tfhe_struct) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
        let _next_tfhe_struct: NextServerKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_server_key() {
        use crate::integer::server_key::CompressedServerKey;
        use next_tfhe::integer::server_key::CompressedServerKey as NextCompressedServerKey;

        use crate::integer::ClientKey;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let tfhe_struct = CompressedServerKey::new_radix_compressed_server_key(&cks);
        let _next_tfhe_struct: NextCompressedServerKey = tfhe_struct.convert_into();
    }
}
