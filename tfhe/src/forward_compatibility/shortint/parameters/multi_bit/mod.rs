use crate::forward_compatibility::ConvertInto;
use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
use next_tfhe::core_crypto::commons::parameters::DynamicDistribution;
use next_tfhe::shortint::ciphertext::MaxNoiseLevel as NextMaxNoiseLevel;
use next_tfhe::shortint::parameters::multi_bit::MultiBitPBSParameters as NextMultiBitPBSParameters;

impl crate::forward_compatibility::ConvertFrom<MultiBitPBSParameters>
    for NextMultiBitPBSParameters
{
    #[inline]
    fn convert_from(value: MultiBitPBSParameters) -> Self {
        let MultiBitPBSParameters {
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
            grouping_factor,
            deterministic_execution,
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
            grouping_factor: grouping_factor.convert_into(),
            deterministic_execution,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::forward_compatibility::ConvertInto;

    #[test]
    fn test_conversion_multi_bit_pbs_parameters() {
        use crate::core_crypto::commons::dispersion::StandardDev;
        use crate::core_crypto::commons::parameters::*;
        use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
        use crate::shortint::{CarryModulus, MessageModulus};
        use next_tfhe::shortint::parameters::multi_bit::MultiBitPBSParameters as NextMultiBitPBSParameters;

        use rand::Rng;

        let mut rng = rand::thread_rng();

        for encryption_key_choice in [EncryptionKeyChoice::Big, EncryptionKeyChoice::Small] {
            for deterministic_execution in [true, false] {
                let tfhe_struct = MultiBitPBSParameters {
                    lwe_dimension: LweDimension(rng.gen()),
                    glwe_dimension: GlweDimension(rng.gen()),
                    polynomial_size: PolynomialSize(rng.gen()),
                    lwe_modular_std_dev: StandardDev(rng.gen()),
                    glwe_modular_std_dev: StandardDev(rng.gen()),
                    pbs_base_log: DecompositionBaseLog(rng.gen()),
                    pbs_level: DecompositionLevelCount(rng.gen()),
                    ks_base_log: DecompositionBaseLog(rng.gen()),
                    ks_level: DecompositionLevelCount(rng.gen()),
                    message_modulus: MessageModulus(rng.gen()),
                    carry_modulus: CarryModulus(rng.gen()),
                    ciphertext_modulus: CiphertextModulus::new_native(),
                    encryption_key_choice,
                    grouping_factor: LweBskGroupingFactor(rng.gen()),
                    deterministic_execution,
                };

                let next_tfhe_struct: NextMultiBitPBSParameters = tfhe_struct.convert_into();

                assert_eq!(
                    next_tfhe_struct.encryption_key_choice,
                    encryption_key_choice.convert_into()
                );
                assert_eq!(
                    next_tfhe_struct.deterministic_execution,
                    deterministic_execution
                );
            }
        }
    }
}
