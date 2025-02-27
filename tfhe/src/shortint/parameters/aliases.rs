use crate::shortint::parameters::{
    current_params, ClassicPBSParameters, CompactPublicKeyEncryptionParameters,
    CompressionParameters, MultiBitPBSParameters, ShortintKeySwitchingParameters,
};

use crate::shortint::parameters::v1_1::{
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
};
use current_params::classic::gaussian::p_fail_2_minus_128::ks_pbs::{
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use current_params::classic::gaussian::p_fail_2_minus_64::ks_pbs::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use current_params::classic::tuniform::p_fail_2_minus_128::ks_pbs::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::classic::tuniform::p_fail_2_minus_64::ks_pbs::V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use current_params::compact_public_key_only::p_fail_2_minus_128::ks_pbs::V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::key_switching::p_fail_2_minus_128::ks_pbs::V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::list_compression::p_fail_2_minus_128::{
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use current_params::list_compression::p_fail_2_minus_64::{
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};
// Aliases

// Compute Gaussian
// 2M128
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

// Used by CRT doctests
pub const PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;

// 2M64
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: ClassicPBSParameters =
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

// Compute TUniform
// 2M128
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

// 2M64
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: ClassicPBSParameters =
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

// Compression Gaussian
// 2M128
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: CompressionParameters =
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

// 2M64
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

// Compression TUniform
// 2M128
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters =
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS: CompressionParameters =
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_MESSAGE_2_CARRY_2: CompressionParameters = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

// 2M64
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

// PKE TUniform
pub const PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompactPublicKeyEncryptionParameters =
    V1_0_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// PKE To Compute Keyswitch
pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ShortintKeySwitchingParameters =
    V1_0_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// GPU TUniform
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_4_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// GPU Gaussian
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_1_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;
