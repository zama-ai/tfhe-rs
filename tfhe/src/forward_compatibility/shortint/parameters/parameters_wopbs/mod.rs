use crate::forward_compatibility::ConvertInto;

use crate::shortint::parameters::parameters_wopbs::WopbsParameters;
use next_tfhe::core_crypto::commons::parameters::DynamicDistribution;
use next_tfhe::shortint::parameters::parameters_wopbs::WopbsParameters as NextWopbsParameters;

impl crate::forward_compatibility::ConvertFrom<WopbsParameters> for NextWopbsParameters {
    #[inline]
    fn convert_from(value: WopbsParameters) -> Self {
        let WopbsParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_level,
            ks_base_log,
            pfks_level,
            pfks_base_log,
            pfks_modular_std_dev,
            cbs_level,
            cbs_base_log,
            message_modulus,
            carry_modulus,
            ciphertext_modulus,
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
            ks_level: ks_level.convert_into(),
            ks_base_log: ks_base_log.convert_into(),
            pfks_level: pfks_level.convert_into(),
            pfks_base_log: pfks_base_log.convert_into(),
            pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
                pfks_modular_std_dev.convert_into(),
            ),
            cbs_level: cbs_level.convert_into(),
            cbs_base_log: cbs_base_log.convert_into(),
            message_modulus: message_modulus.convert_into(),
            carry_modulus: carry_modulus.convert_into(),
            ciphertext_modulus: ciphertext_modulus.convert_into(),
            encryption_key_choice: encryption_key_choice.convert_into(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_wopbs_parameters() {
        use next_tfhe::shortint::parameters::parameters_wopbs::WopbsParameters as NextWopbsParameters;

        use crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let tfhe_struct = WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let _next_tfhe_struct: NextWopbsParameters = tfhe_struct.convert_into();
    }
}
