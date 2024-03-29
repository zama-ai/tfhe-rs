use crate::forward_compatibility::ConvertInto;

use crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters;
use next_tfhe::shortint::parameters::key_switching::ShortintKeySwitchingParameters as NextShortintKeySwitchingParameters;

impl crate::forward_compatibility::ConvertFrom<ShortintKeySwitchingParameters>
    for NextShortintKeySwitchingParameters
{
    #[inline]
    fn convert_from(value: ShortintKeySwitchingParameters) -> Self {
        let ShortintKeySwitchingParameters {
            ks_base_log,
            ks_level,
        } = value;
        Self {
            ks_base_log: ks_base_log.convert_into(),
            ks_level: ks_level.convert_into(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_shortint_key_switching_parameters() {
        use crate::core_crypto::commons::parameters::*;
        use crate::shortint::parameters::key_switching::ShortintKeySwitchingParameters;
        use next_tfhe::shortint::parameters::key_switching::ShortintKeySwitchingParameters as NextShortintKeySwitchingParameters;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = ShortintKeySwitchingParameters {
            ks_base_log: DecompositionBaseLog(rng.gen()),
            ks_level: DecompositionLevelCount(rng.gen()),
        };

        let _next_tfhe_struct: NextShortintKeySwitchingParameters = tfhe_struct.convert_into();
    }
}
