use crate::boolean::parameters::BooleanParameters;
use crate::forward_compatibility::ConvertInto;
use next_tfhe::boolean::parameters::BooleanParameters as NextBooleanParameters;
use next_tfhe::core_crypto::commons::parameters::DynamicDistribution;

impl crate::forward_compatibility::ConvertFrom<BooleanParameters> for NextBooleanParameters {
    #[inline]
    fn convert_from(value: BooleanParameters) -> Self {
        let BooleanParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            encryption_key_choice,
        } = value;
        Self {
            lwe_dimension: lwe_dimension.convert_into(),
            glwe_dimension: glwe_dimension.convert_into(),
            polynomial_size: polynomial_size.convert_into(),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
                lwe_modular_std_dev.convert_into(),
            ),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
                glwe_modular_std_dev.convert_into(),
            ),
            pbs_base_log: pbs_base_log.convert_into(),
            pbs_level: pbs_level.convert_into(),
            ks_base_log: ks_base_log.convert_into(),
            ks_level: ks_level.convert_into(),
            encryption_key_choice: encryption_key_choice.convert_into(),
        }
    }
}

use crate::boolean::parameters::BooleanKeySwitchingParameters;
use next_tfhe::boolean::parameters::BooleanKeySwitchingParameters as NextBooleanKeySwitchingParameters;

impl crate::forward_compatibility::ConvertFrom<BooleanKeySwitchingParameters>
    for NextBooleanKeySwitchingParameters
{
    #[inline]
    fn convert_from(value: BooleanKeySwitchingParameters) -> Self {
        let BooleanKeySwitchingParameters {
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
    fn test_conversion_boolean_parameters() {
        use crate::boolean::parameters::BooleanParameters;
        use crate::core_crypto::commons::dispersion::StandardDev;
        use crate::core_crypto::commons::parameters::*;
        use next_tfhe::boolean::parameters::BooleanParameters as NextBooleanParameters;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        for encryption_key_choice in [EncryptionKeyChoice::Big, EncryptionKeyChoice::Small] {
            let tfhe_struct = BooleanParameters {
                lwe_dimension: LweDimension(rng.gen()),
                glwe_dimension: GlweDimension(rng.gen()),
                polynomial_size: PolynomialSize(rng.gen()),
                lwe_modular_std_dev: StandardDev(rng.gen()),
                glwe_modular_std_dev: StandardDev(rng.gen()),
                pbs_base_log: DecompositionBaseLog(rng.gen()),
                pbs_level: DecompositionLevelCount(rng.gen()),
                ks_base_log: DecompositionBaseLog(rng.gen()),
                ks_level: DecompositionLevelCount(rng.gen()),
                encryption_key_choice,
            };

            let _next_tfhe_struct: NextBooleanParameters = tfhe_struct.convert_into();
        }
    }

    #[test]
    fn test_conversion_boolean_key_switching_parameters() {
        use crate::boolean::parameters::BooleanKeySwitchingParameters;
        use crate::core_crypto::commons::parameters::*;
        use next_tfhe::boolean::parameters::BooleanKeySwitchingParameters as NextBooleanKeySwitchingParameters;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = BooleanKeySwitchingParameters {
            ks_base_log: DecompositionBaseLog(rng.gen()),
            ks_level: DecompositionLevelCount(rng.gen()),
        };

        let _next_tfhe_struct: NextBooleanKeySwitchingParameters = tfhe_struct.convert_into();
    }
}
