use crate::forward_compatibility::ConvertInto;
use crate::shortint::key_switching_key::KeySwitchingKey;
use next_tfhe::shortint::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

impl crate::forward_compatibility::ConvertFrom<KeySwitchingKey> for NextKeySwitchingKey {
    #[inline]
    fn convert_from(value: KeySwitchingKey) -> Self {
        let KeySwitchingKey {
            key_switching_key,
            dest_server_key,
            src_server_key,
            cast_rshift,
        } = value;

        Self::from_raw_parts(
            key_switching_key.convert_into(),
            dest_server_key.convert_into(),
            src_server_key.convert_into(),
            cast_rshift.convert_into(),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_key_switching_key() {
        use crate::shortint::key_switching_key::KeySwitchingKey;
        use next_tfhe::shortint::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

        use crate::shortint::gen_keys;
        use crate::shortint::parameters::key_switching::PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS;
        use crate::shortint::parameters::{
            PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        };

        let (cks1, sks1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
        let (cks2, sks2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let tfhe_struct = KeySwitchingKey::new(
            (&cks1, &sks1),
            (&cks2, &sks2),
            PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
        );

        let _next_tfhe_struct: NextKeySwitchingKey = tfhe_struct.convert_into();
    }
}
