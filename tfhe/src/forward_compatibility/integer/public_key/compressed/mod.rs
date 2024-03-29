use crate::forward_compatibility::ConvertInto;

use crate::integer::public_key::compressed::CompressedPublicKey;
use next_tfhe::integer::public_key::compressed::CompressedPublicKey as NextCompressedPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedPublicKey> for NextCompressedPublicKey {
    #[inline]
    fn convert_from(value: CompressedPublicKey) -> Self {
        let CompressedPublicKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compressed_public_key() {
        use crate::integer::public_key::compressed::CompressedPublicKey;
        use next_tfhe::integer::public_key::compressed::CompressedPublicKey as NextCompressedPublicKey;

        use crate::integer::{gen_keys, IntegerKeyKind};
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS, IntegerKeyKind::Radix);

        let tfhe_struct = CompressedPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedPublicKey = tfhe_struct.convert_into();
    }
}
