//! Implement bridge between native tfhe Parameters and Hpu one
use tfhe_hpu_backend::prelude::*;

use crate::shortint::parameters::{
    CiphertextModulus32, DynamicDistribution, KeySwitch32PBSParameters,
};
use crate::shortint::prelude::*;

impl From<&HpuModulusSwitchType> for ModulusSwitchType {
    fn from(value: &HpuModulusSwitchType) -> Self {
        match value {
            HpuModulusSwitchType::Standard => Self::Standard,
            HpuModulusSwitchType::CenteredMeanNoiseReduction => Self::CenteredMeanNoiseReduction,
        }
    }
}

#[allow(clippy::fallible_impl_from)]
impl From<&HpuParameters> for KeySwitch32PBSParameters {
    fn from(value: &HpuParameters) -> Self {
        let lwe_noise_distribution = match value.pbs_params.lwe_noise_distribution {
            HpuNoiseDistributionInput::GaussianStdDev(std_dev) => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(std_dev))
            }
            HpuNoiseDistributionInput::TUniformBound(log2_bound) => {
                DynamicDistribution::new_t_uniform(log2_bound)
            }
        };
        let glwe_noise_distribution = match value.pbs_params.glwe_noise_distribution {
            HpuNoiseDistributionInput::GaussianStdDev(std_dev) => {
                DynamicDistribution::new_gaussian_from_std_dev(StandardDev(std_dev))
            }
            HpuNoiseDistributionInput::TUniformBound(log2_bound) => {
                DynamicDistribution::new_t_uniform(log2_bound)
            }
        };

        Self {
            lwe_dimension: LweDimension(value.pbs_params.lwe_dimension),
            glwe_dimension: GlweDimension(value.pbs_params.glwe_dimension),
            polynomial_size: PolynomialSize(value.pbs_params.polynomial_size),
            lwe_noise_distribution,
            glwe_noise_distribution,
            pbs_base_log: DecompositionBaseLog(value.pbs_params.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_params.pbs_level),
            ks_base_log: DecompositionBaseLog(value.pbs_params.ks_base_log),
            ks_level: DecompositionLevelCount(value.pbs_params.ks_level),
            message_modulus: MessageModulus(1 << value.pbs_params.message_width),
            carry_modulus: CarryModulus(1 << value.pbs_params.carry_width),
            max_noise_level: MaxNoiseLevel::new(5),
            log2_p_fail: value.pbs_params.log2_p_fail,
            post_keyswitch_ciphertext_modulus: CiphertextModulus32::try_new_power_of_2(
                value.ks_params.width,
            )
            .unwrap(),
            ciphertext_modulus: CiphertextModulus::try_new_power_of_2(
                value.pbs_params.ciphertext_width,
            )
            .unwrap(),
            modulus_switch_noise_reduction_params: ModulusSwitchType::from(
                &value.pbs_params.modulus_switch_type,
            ),
        }
    }
}

impl From<HpuParameters> for KeySwitch32PBSParameters {
    fn from(value: HpuParameters) -> Self {
        Self::from(&value)
    }
}
