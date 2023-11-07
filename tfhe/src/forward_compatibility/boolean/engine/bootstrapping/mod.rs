use crate::forward_compatibility::ConvertInto;

use crate::boolean::engine::bootstrapping::ServerKey;
use next_tfhe::boolean::engine::bootstrapping::ServerKey as NextServerKey;

impl crate::forward_compatibility::ConvertFrom<ServerKey> for NextServerKey {
    #[inline]
    fn convert_from(value: ServerKey) -> Self {
        let ServerKey {
            bootstrapping_key,
            key_switching_key,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            bootstrapping_key.convert_into(),
            key_switching_key.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

use crate::boolean::engine::bootstrapping::CompressedServerKey;
use next_tfhe::boolean::engine::bootstrapping::CompressedServerKey as NextCompressedServerKey;

impl crate::forward_compatibility::ConvertFrom<CompressedServerKey> for NextCompressedServerKey {
    #[inline]
    fn convert_from(value: CompressedServerKey) -> Self {
        let CompressedServerKey {
            bootstrapping_key,
            key_switching_key,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            bootstrapping_key.convert_into(),
            key_switching_key.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_server_key() {
        use next_tfhe::boolean::engine::bootstrapping::ServerKey as NextServerKey;

        use crate::boolean::gen_keys;

        let (_cks, tfhe_struct) = gen_keys();
        let _next_tfhe_struct: NextServerKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_server_key() {
        use crate::boolean::engine::bootstrapping::CompressedServerKey;
        use next_tfhe::boolean::engine::bootstrapping::CompressedServerKey as NextCompressedServerKey;

        use crate::boolean::client_key::ClientKey;
        use crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS;

        let cks = ClientKey::new(&DEFAULT_PARAMETERS_KS_PBS);
        let tfhe_struct = CompressedServerKey::new(&cks);
        let _next_tfhe_struct: NextCompressedServerKey = tfhe_struct.convert_into();
    }
}
