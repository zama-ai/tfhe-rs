use crate::forward_compatibility::ConvertInto;

use crate::integer::public_key::compact::CompactPublicKey;
use next_tfhe::integer::public_key::compact::CompactPublicKey as NextCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompactPublicKey> for NextCompactPublicKey {
    #[inline]
    fn convert_from(value: CompactPublicKey) -> Self {
        let CompactPublicKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

use crate::integer::public_key::compact::CompressedCompactPublicKey;
use next_tfhe::integer::public_key::compact::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedCompactPublicKey>
    for NextCompressedCompactPublicKey
{
    #[inline]
    fn convert_from(value: CompressedCompactPublicKey) -> Self {
        let CompressedCompactPublicKey { key } = value;

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compact_public_key() {
        use crate::integer::public_key::compact::CompactPublicKey;
        use next_tfhe::integer::public_key::compact::CompactPublicKey as NextCompactPublicKey;

        use crate::integer::{gen_keys, IntegerKeyKind};
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS, IntegerKeyKind::Radix);
        let tfhe_struct = CompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_compact_public_key() {
        use crate::integer::public_key::compact::CompressedCompactPublicKey;
        use next_tfhe::integer::public_key::compact::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

        use crate::integer::{gen_keys, IntegerKeyKind};
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS, IntegerKeyKind::Radix);
        let tfhe_struct = CompressedCompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompressedCompactPublicKey = tfhe_struct.convert_into();
    }
}
