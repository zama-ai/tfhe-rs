use crate::shortint::parameters::CompressionParameters;

/// p-fail = 2^-129.053, algorithmic cost ~ 41458
pub const V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters =
    crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

/// p-fail = 2^-129.053, algorithmic cost ~ 41458
pub const V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters = crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

/// p-fail = 2^-128.0, algorithmic cost ~ 42199
pub const V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: CompressionParameters =
    crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

/// p-fail = 2^-128.0, algorithmic cost ~ 42199
pub const V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: CompressionParameters = crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
