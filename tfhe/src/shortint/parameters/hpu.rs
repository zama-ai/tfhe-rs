//! Implement bridge between native tfhe Parameters and Hpu one
use tfhe_hpu_backend::prelude::*;

use crate::shortint::parameters::DynamicDistribution;
use crate::shortint::prelude::*;

impl From<&HpuParameters> for ClassicPBSParameters {
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

        Self::new(
            LweDimension(value.pbs_params.lwe_dimension),
            GlweDimension(value.pbs_params.glwe_dimension),
            PolynomialSize(value.pbs_params.polynomial_size),
            lwe_noise_distribution,
            glwe_noise_distribution,
            DecompositionBaseLog(value.pbs_params.pbs_base_log),
            DecompositionLevelCount(value.pbs_params.pbs_level),
            DecompositionBaseLog(value.pbs_params.ks_base_log),
            DecompositionLevelCount(value.pbs_params.ks_level),
            MessageModulus(1 << value.pbs_params.message_width),
            CarryModulus(1 << value.pbs_params.carry_width),
            MaxNoiseLevel::new(5),
            -64.0, // TODO fixme
            CiphertextModulus::try_new_power_of_2(value.pbs_params.ciphertext_width).unwrap(),
            EncryptionKeyChoice::Big,
            None,
        )
    }
}

impl From<HpuParameters> for ClassicPBSParameters {
    fn from(value: HpuParameters) -> Self {
        Self::from(&value)
    }
}
