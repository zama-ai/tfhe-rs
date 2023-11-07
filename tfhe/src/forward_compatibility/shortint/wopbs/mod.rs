use crate::forward_compatibility::ConvertInto;

use crate::shortint::wopbs::WopbsKey;
use next_tfhe::shortint::wopbs::WopbsKey as NextWopbsKey;

impl crate::forward_compatibility::ConvertFrom<WopbsKey> for NextWopbsKey {
    #[inline]
    fn convert_from(value: WopbsKey) -> Self {
        let WopbsKey {
            wopbs_server_key,
            pbs_server_key,
            cbs_pfpksk,
            ksk_pbs_to_wopbs,
            param,
        } = value;

        Self::from_raw_parts(
            wopbs_server_key.convert_into(),
            pbs_server_key.convert_into(),
            cbs_pfpksk.convert_into(),
            ksk_pbs_to_wopbs.convert_into(),
            param.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_wopbs_key() {
        use crate::shortint::wopbs::WopbsKey;
        use next_tfhe::shortint::wopbs::WopbsKey as NextWopbsKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct =
            WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let _next_tfhe_struct: NextWopbsKey = tfhe_struct.convert_into();
    }
}
