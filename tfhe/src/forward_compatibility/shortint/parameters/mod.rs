pub mod key_switching;
pub mod multi_bit;
pub mod parameters_wopbs;

use crate::forward_compatibility::ConvertInto;

use crate::shortint::parameters::MessageModulus;
use next_tfhe::core_crypto::commons::parameters::DynamicDistribution;
use next_tfhe::shortint::ciphertext::MaxNoiseLevel as NextMaxNoiseLevel;
use next_tfhe::shortint::parameters::MessageModulus as NextMessageModulus;

impl crate::forward_compatibility::ConvertFrom<MessageModulus> for NextMessageModulus {
    #[inline]
    fn convert_from(value: MessageModulus) -> Self {
        let MessageModulus(field_0) = value;
        Self(field_0)
    }
}

use crate::shortint::parameters::CarryModulus;
use next_tfhe::shortint::parameters::CarryModulus as NextCarryModulus;

impl crate::forward_compatibility::ConvertFrom<CarryModulus> for NextCarryModulus {
    #[inline]
    fn convert_from(value: CarryModulus) -> Self {
        let CarryModulus(field_0) = value;
        Self(field_0)
    }
}

use crate::shortint::parameters::ClassicPBSParameters;
use next_tfhe::shortint::parameters::ClassicPBSParameters as NextClassicPBSParameters;

impl crate::forward_compatibility::ConvertFrom<ClassicPBSParameters> for NextClassicPBSParameters {
    #[inline]
    fn convert_from(value: ClassicPBSParameters) -> Self {
        let ClassicPBSParameters {
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
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
            ks_base_log: ks_base_log.convert_into(),
            ks_level: ks_level.convert_into(),
            message_modulus: message_modulus.convert_into(),
            carry_modulus: carry_modulus.convert_into(),
            max_noise_level: NextMaxNoiseLevel::from_msg_carry_modulus(
                message_modulus.convert_into(),
                carry_modulus.convert_into(),
            ),
            // Unknown value is log2_p_fail = 1.0
            log2_p_fail: 1.0,
            ciphertext_modulus: ciphertext_modulus.convert_into(),
            encryption_key_choice: encryption_key_choice.convert_into(),
        }
    }
}

use crate::shortint::parameters::PBSParameters;
use next_tfhe::shortint::parameters::PBSParameters as NextPBSParameters;

impl crate::forward_compatibility::ConvertFrom<PBSParameters> for NextPBSParameters {
    #[inline]
    fn convert_from(value: PBSParameters) -> Self {
        match value {
            PBSParameters::PBS(params) => Self::PBS(params.convert_into()),
            PBSParameters::MultiBitPBS(params) => Self::MultiBitPBS(params.convert_into()),
        }
    }
}

use crate::shortint::parameters::ShortintParameterSet;
use next_tfhe::shortint::parameters::ShortintParameterSet as NextShortintParameterSet;

impl crate::forward_compatibility::ConvertFrom<ShortintParameterSet> for NextShortintParameterSet {
    #[inline]
    fn convert_from(value: ShortintParameterSet) -> Self {
        match (value.pbs_parameters(), value.wopbs_parameters()) {
            (None, None) => unreachable!(),
            (None, Some(params)) => Self::new_wopbs_param_set(params.convert_into()),
            (Some(params), None) => Self::new_pbs_param_set(params.convert_into()),
            (Some(pbs_params), Some(wopbs_params)) => {
                let pbs_params: NextPBSParameters = pbs_params.convert_into();
                Self::try_new_pbs_and_wopbs_param_set((pbs_params, wopbs_params.convert_into()))
                    .unwrap()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_message_modulus() {
        use crate::shortint::parameters::MessageModulus;
        use next_tfhe::shortint::parameters::MessageModulus as NextMessageModulus;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = MessageModulus(rng.gen());

        let next_tfhe_struct: NextMessageModulus = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.0, next_tfhe_struct.0);
    }

    #[test]
    fn test_conversion_carry_modulus() {
        use crate::shortint::parameters::CarryModulus;
        use next_tfhe::shortint::parameters::CarryModulus as NextCarryModulus;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        let tfhe_struct = CarryModulus(rng.gen());

        let next_tfhe_struct: NextCarryModulus = tfhe_struct.convert_into();

        assert_eq!(tfhe_struct.0, next_tfhe_struct.0);
    }

    #[test]
    fn test_conversion_classic_pbs_parameters() {
        use next_tfhe::shortint::parameters::ClassicPBSParameters as NextClassicPBSParameters;

        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        let tfhe_struct = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        let _next_tfhe_struct: NextClassicPBSParameters = tfhe_struct.convert_into();
    }

    #[test]
    fn test_conversion_shortint_parameter_set() {
        use crate::shortint::parameters::ShortintParameterSet;
        use next_tfhe::shortint::parameters::ShortintParameterSet as NextShortintParameterSet;

        use crate::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

        {
            let tfhe_struct =
                ShortintParameterSet::new_pbs_param_set(PARAM_MESSAGE_2_CARRY_2_KS_PBS.into());
            let _next_tfhe_struct: NextShortintParameterSet = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct =
                ShortintParameterSet::new_wopbs_param_set(WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
            let _next_tfhe_struct: NextShortintParameterSet = tfhe_struct.convert_into();
        }

        {
            let tfhe_struct = ShortintParameterSet::try_new_pbs_and_wopbs_param_set((
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            ));

            assert!(tfhe_struct.is_ok());
            let tfhe_struct = tfhe_struct.unwrap();
            let _next_tfhe_struct: NextShortintParameterSet = tfhe_struct.convert_into();
        }
    }
}
