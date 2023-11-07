use crate::forward_compatibility::ConvertInto;

use crate::integer::client_key::CrtClientKey;
use next_tfhe::integer::client_key::CrtClientKey as NextCrtClientKey;

impl crate::forward_compatibility::ConvertFrom<CrtClientKey> for NextCrtClientKey {
    #[inline]
    fn convert_from(value: CrtClientKey) -> Self {
        let key = value.as_ref().to_owned();
        let moduli = value.moduli().to_vec();

        Self::from((key.convert_into(), moduli))
    }
}

use crate::integer::client_key::RadixClientKey;
use next_tfhe::integer::client_key::RadixClientKey as NextRadixClientKey;

impl crate::forward_compatibility::ConvertFrom<RadixClientKey> for NextRadixClientKey {
    #[inline]
    fn convert_from(value: RadixClientKey) -> Self {
        let key = value.as_ref().to_owned();
        let num_blocks = value.num_blocks();

        Self::from((key.convert_into(), num_blocks))
    }
}

use crate::integer::client_key::ClientKey;
use next_tfhe::integer::client_key::ClientKey as NextClientKey;

impl crate::forward_compatibility::ConvertFrom<ClientKey> for NextClientKey {
    #[inline]
    fn convert_from(value: ClientKey) -> Self {
        let ClientKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_crt_client_key() {
        use crate::integer::client_key::CrtClientKey;
        use next_tfhe::integer::client_key::CrtClientKey as NextCrtClientKey;

        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let tfhe_struct = CrtClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS, vec![2u64, 3u64]);
        let _next_tfhe_struct: NextCrtClientKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_radix_client_key() {
        use crate::integer::client_key::RadixClientKey;
        use next_tfhe::integer::client_key::RadixClientKey as NextRadixClientKey;

        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let tfhe_struct = RadixClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 32);
        let _next_tfhe_struct: NextRadixClientKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_client_key() {
        use crate::integer::client_key::ClientKey;
        use next_tfhe::integer::client_key::ClientKey as NextClientKey;

        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let tfhe_struct = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let _next_tfhe_struct: NextClientKey = tfhe_struct.convert_into();
    }
}
