use crate::forward_compatibility::ConvertInto;

use crate::boolean::key_switching_key::KeySwitchingKey;
use next_tfhe::boolean::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

impl crate::forward_compatibility::ConvertFrom<KeySwitchingKey> for NextKeySwitchingKey {
    #[inline]
    fn convert_from(value: KeySwitchingKey) -> Self {
        let KeySwitchingKey { key_switching_key } = value;

        Self::from_raw_parts(key_switching_key.convert_into())
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_key_switching_key() {
        use crate::boolean::key_switching_key::KeySwitchingKey;
        use next_tfhe::boolean::key_switching_key::KeySwitchingKey as NextKeySwitchingKey;

        use crate::boolean::gen_keys;
        use crate::boolean::parameters::BooleanKeySwitchingParameters;

        let (cks1, _sks1) = gen_keys();
        let (cks2, _sks2) = gen_keys();

        let ksk_params = BooleanKeySwitchingParameters::new(
            cks2.parameters.ks_base_log,
            cks2.parameters.ks_level,
        );

        let tfhe_struct = KeySwitchingKey::new(&cks1, &cks2, ksk_params);
        let _next_tfhe_struct: NextKeySwitchingKey = tfhe_struct.convert_into();
    }
}
