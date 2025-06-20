use crate::core_crypto::prelude::DynamicDistribution;
use crate::shortint::parameters::{
    CiphertextModulus32, KeySwitch32PBSParameters, LweCiphertextCount,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    RSigmaFactor, Variance,
};
use crate::shortint::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::shortint::{CarryModulus, CiphertextModulus, MaxNoiseLevel, MessageModulus};

// p-fail = 2^-129.358, algorithmic cost ~ 113, 2-norm = 5
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000140546154228955)
pub const V1_2_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(918),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(13),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -129.358380844,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new_native(),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1449),
                ms_bound: NoiseEstimationMeasureBound(67108864f64),
                ms_r_sigma_factor: RSigmaFactor(13.179851302864899f64),
                ms_input_variance: Variance(2.63039392929833E-7f64),
            },
        ),
    };
