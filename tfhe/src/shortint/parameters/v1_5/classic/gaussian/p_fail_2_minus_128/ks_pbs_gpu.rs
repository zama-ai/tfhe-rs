use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweDimension,
    MaxNoiseLevel, MessageModulus, PolynomialSize,
};
use crate::shortint::prelude::{ModulusSwitchType, StandardDev};

/// p-fail = 2^-131.084, algorithmic cost ~ 90.5, 2-norm = 3
pub const V1_5_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(737),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.894717698310226e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601874e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -128.186,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };
