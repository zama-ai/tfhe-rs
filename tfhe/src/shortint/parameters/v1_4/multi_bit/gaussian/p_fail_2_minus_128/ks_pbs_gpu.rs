use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweDimension,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PolynomialSize, StandardDev,
};
/// p-fail = 2^-128.997, algorithmic cost ~ 62, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.138, algorithmic cost ~ 178, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-131.491, algorithmic cost ~ 1365, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.179, algorithmic cost ~ 11257, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-129.466, algorithmic cost ~ 80, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.606, algorithmic cost ~ 140, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-129.012, algorithmic cost ~ 1310, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-131.073, algorithmic cost ~ 10902, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.034, algorithmic cost ~ 76, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(736),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9276917419403266e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -128.034,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-129.112, algorithmic cost ~ 95, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.201, algorithmic cost ~ 781, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
/// p-fail = 2^-128.084, algorithmic cost ~ 6900, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128;
