use crate::forward_compatibility::ConvertInto;

use crate::integer::wopbs::WopbsKey;
use next_tfhe::integer::wopbs::WopbsKey as NextWopbsKey;

impl crate::forward_compatibility::ConvertFrom<WopbsKey> for NextWopbsKey {
    #[inline]
    fn convert_from(value: WopbsKey) -> Self {
        let wopbskey = value.into_raw_parts();

        Self::from_raw_parts(wopbskey.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_wopbs_key() {
        use crate::integer::wopbs::WopbsKey;
        use next_tfhe::integer::wopbs::WopbsKey as NextWopbsKey;

        use crate::integer::{gen_keys, IntegerKeyKind};
        use crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS, IntegerKeyKind::Radix);

        let tfhe_struct =
            WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let _next_tfhe_struct: NextWopbsKey = tfhe_struct.convert_into();
    }
}
