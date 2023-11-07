use crate::forward_compatibility::ConvertInto;

use crate::shortint::public_key::compact::CompactPublicKey;
use next_tfhe::shortint::public_key::compact::CompactPublicKey as NextCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompactPublicKey> for NextCompactPublicKey {
    #[inline]
    fn convert_from(value: CompactPublicKey) -> Self {
        let CompactPublicKey {
            key,
            parameters,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            key.convert_into(),
            parameters.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

use crate::shortint::public_key::compact::CompressedCompactPublicKey;
use next_tfhe::shortint::public_key::compact::CompressedCompactPublicKey as NextCompressedCompactPublicKey;

impl crate::forward_compatibility::ConvertFrom<CompressedCompactPublicKey>
    for NextCompressedCompactPublicKey
{
    #[inline]
    fn convert_from(value: CompressedCompactPublicKey) -> Self {
        let CompressedCompactPublicKey {
            key,
            parameters,
            pbs_order,
        } = value;

        Self::from_raw_parts(
            key.convert_into(),
            parameters.convert_into(),
            pbs_order.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_compact_public_key() {
        use crate::shortint::public_key::compact::CompactPublicKey;
        use next_tfhe::shortint::public_key::compact::CompactPublicKey as NextCompactPublicKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = CompactPublicKey::new(&cks);
        let _next_tfhe_struct: NextCompactPublicKey = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compressed_compact_public_key() {
        use crate::shortint::public_key::compact::CompressedCompactPublicKey;
        use next_tfhe::shortint::public_key::compact::{
            CompactPublicKey as NextCompactPublicKey,
            CompressedCompactPublicKey as NextCompressedCompactPublicKey,
        };

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = CompressedCompactPublicKey::new(&cks);
        let next_tfhe_struct: NextCompressedCompactPublicKey = tfhe_struct.clone().convert_into();

        let tfhe_decompressed = tfhe_struct.decompress();
        let next_tfhe_decompressed_converted: NextCompactPublicKey =
            tfhe_decompressed.convert_into();

        let next_tfhe_decompressed = next_tfhe_struct.decompress();

        assert_eq!(next_tfhe_decompressed_converted, next_tfhe_decompressed);
    }
}
