use crate::shortint::parameters::CompressionParameters;

/// p-fail = 2^-72.052, algorithmic cost ~ 42700
pub const V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

/// p-fail = 2^-72.052, algorithmic cost ~ 42700
pub const V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters = crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

/// p-fail = 2^-64.174, algorithmic cost ~ 58234
pub const V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

/// p-fail = 2^-64.174, algorithmic cost ~ 58234
pub const V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters = crate::shortint::parameters::v1_3::V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
