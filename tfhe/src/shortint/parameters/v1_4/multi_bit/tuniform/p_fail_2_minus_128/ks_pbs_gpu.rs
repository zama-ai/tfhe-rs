use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweDimension,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PolynomialSize,
};
/// p-fail = 2^-136.056, algorithmic cost ~ 63, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-140.341, algorithmic cost ~ 188, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-135.674, algorithmic cost ~ 1390, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-140.409, algorithmic cost ~ 11612, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-131.536, algorithmic cost ~ 86, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-128.29, algorithmic cost ~ 144, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-147.007, algorithmic cost ~ 1342, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-131.906, algorithmic cost ~ 11197, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-145.020, algorithmic cost ~ 79, 2-norm = 3
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(760),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(49),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -145.020,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
/// p-fail = 2^-134.345, algorithmic cost ~ 100, 2-norm = 5
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-130.951, algorithmic cost ~ 810, 2-norm = 9
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-128.146, algorithmic cost ~ 7147, 2-norm = 17
pub const V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: MultiBitPBSParameters = crate::shortint::parameters::v1_1::V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128;
