use crate::forward_compatibility::ConvertInto;
use crate::integer::ciphertext::IntegerCiphertext;
use crate::shortint::Ciphertext;
use next_tfhe::shortint::Ciphertext as NextCiphertext;

use crate::integer::ciphertext::BaseRadixCiphertext;
use next_tfhe::integer::ciphertext::BaseRadixCiphertext as NextBaseRadixCiphertext;

impl crate::forward_compatibility::ConvertFrom<BaseRadixCiphertext<Ciphertext>>
    for NextBaseRadixCiphertext<NextCiphertext>
{
    #[inline]
    fn convert_from(value: BaseRadixCiphertext<Ciphertext>) -> Self {
        let blocks: Vec<NextCiphertext> = value
            .blocks()
            .iter()
            .map(|block| block.clone().convert_into())
            .collect();
        blocks.into()
    }
}

use crate::integer::ciphertext::CompactCiphertextList;
use next_tfhe::integer::ciphertext::CompactCiphertextList as NextCompactCiphertextList;

impl crate::forward_compatibility::ConvertFrom<CompactCiphertextList>
    for NextCompactCiphertextList
{
    #[inline]
    fn convert_from(value: CompactCiphertextList) -> Self {
        let CompactCiphertextList {
            ct_list,
            num_blocks_per_integer,
        } = value;

        Self::from_raw_parts(
            ct_list.convert_into(),
            num_blocks_per_integer.convert_into(),
        )
    }
}

use crate::integer::ciphertext::BaseSignedRadixCiphertext;
use next_tfhe::integer::ciphertext::BaseSignedRadixCiphertext as NextBaseSignedRadixCiphertext;

impl crate::forward_compatibility::ConvertFrom<BaseSignedRadixCiphertext<Ciphertext>>
    for NextBaseSignedRadixCiphertext<NextCiphertext>
{
    #[inline]
    fn convert_from(value: BaseSignedRadixCiphertext<Ciphertext>) -> Self {
        let blocks: Vec<NextCiphertext> = value
            .blocks()
            .iter()
            .map(|block| block.clone().convert_into())
            .collect();
        blocks.into()
    }
}

use crate::integer::ciphertext::BaseCrtCiphertext;
use next_tfhe::integer::ciphertext::BaseCrtCiphertext as NextBaseCrtCiphertext;

impl crate::forward_compatibility::ConvertFrom<BaseCrtCiphertext<Ciphertext>>
    for NextBaseCrtCiphertext<Ciphertext>
{
    #[inline]
    fn convert_from(value: BaseCrtCiphertext<Ciphertext>) -> Self {
        let moduli = value.moduli();
        let blocks = value.blocks().to_vec();

        (blocks, moduli).into()
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_base_radix_ciphertext() {
        use next_tfhe::integer::ciphertext::BaseRadixCiphertext as NextBaseRadixCiphertext;

        use crate::integer::gen_keys_radix;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
        let tfhe_struct = cks.encrypt(42u64);
        let _next_tfhe_struct: NextBaseRadixCiphertext<_> = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_compact_ciphertext_list() {
        use next_tfhe::integer::ciphertext::CompactCiphertextList as NextCompactCiphertextList;

        use crate::integer::gen_keys_radix;
        use crate::integer::public_key::CompactPublicKey;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;

        let (cks, _sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS, 4);
        let cpk = CompactPublicKey::new(cks.as_ref());

        let tfhe_struct = cpk.encrypt_radix_compact(42u64, 4);
        let _next_tfhe_struct: NextCompactCiphertextList = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_base_signed_radix_ciphertext() {
        use next_tfhe::integer::ciphertext::BaseSignedRadixCiphertext as NextBaseSignedRadixCiphertext;

        use crate::integer::gen_keys_radix;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 4);
        let tfhe_struct = cks.encrypt_signed(-42i64);
        let _next_tfhe_struct: NextBaseSignedRadixCiphertext<_> = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_base_crt_ciphertext() {
        use next_tfhe::integer::ciphertext::BaseCrtCiphertext as NextBaseCrtCiphertext;

        use crate::integer::gen_keys_crt;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, _sks) = gen_keys_crt(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            vec![3u64, 11, 13, 19, 23, 29, 31, 32],
        );

        let tfhe_struct = cks.encrypt(32);
        let _next_tfhe_struct: NextBaseCrtCiphertext<_> = tfhe_struct.convert_into();
    }
}
