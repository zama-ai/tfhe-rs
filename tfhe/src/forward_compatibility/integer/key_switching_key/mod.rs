use crate::forward_compatibility::ConvertInto;

use crate::integer::key_switching_key::KeySwitchingKey;
use next_tfhe::integer::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

impl crate::forward_compatibility::ConvertFrom<KeySwitchingKey> for NextKeySwitchingKey {
    #[inline]
    fn convert_from(value: KeySwitchingKey) -> Self {
        let key = value.into_raw_parts();

        Self::from_raw_parts(key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_key_switching_key() {
        use crate::integer::key_switching_key::KeySwitchingKey;
        use next_tfhe::integer::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

        use crate::integer::gen_keys;
        use crate::shortint::parameters::{
            ShortintKeySwitchingParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
        };

        let (cks1, sks1) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let (cks2, sks2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let ksk_params = ShortintKeySwitchingParameters::new(
            cks2.parameters().ks_base_log(),
            cks2.parameters().ks_level(),
        );
        let tfhe_struct = KeySwitchingKey::new((&cks1, &sks1), (&cks2, &sks2), ksk_params);

        let _next_tfhe_struct: NextKeySwitchingKey = tfhe_struct.convert_into();
    }
}
