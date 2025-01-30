use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{
    CarryModulus, ClassicPBSParameters, MessageModulus, ModulusSwitchNoiseReductionParams,
};

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: ClassicPBSParameters =
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

pub const V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(918),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -129.1531929955725,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1449),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
            ms_input_variance: Variance(2.63039184094559E-7f64),
        }),
    };

// security = 132 bits, p-fail = 2^-71.625
pub const V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -71.625,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: None,
    };
