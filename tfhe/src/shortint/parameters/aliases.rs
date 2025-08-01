use crate::shortint::parameters::{
    current_params, ClassicPBSParameters, CompactPublicKeyEncryptionParameters,
    CompressionParameters, MultiBitPBSParameters, NoiseSquashingParameters,
    ShortintKeySwitchingParameters,
};

use crate::shortint::parameters::current_params::key_switching::p_fail_2_minus_128::ks_pbs_gpu::V1_3_PARAM_MULTI_BIT_GROUP_4_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::v1_3::V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::classic::gaussian::p_fail_2_minus_128::ks_pbs::{
    V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_3_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use current_params::classic::gaussian::p_fail_2_minus_64::ks_pbs::V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
use current_params::classic::tuniform::p_fail_2_minus_128::ks_pbs::V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::classic::tuniform::p_fail_2_minus_64::ks_pbs::V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use current_params::compact_public_key_only::p_fail_2_minus_128::ks_pbs::V1_3_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::key_switching::p_fail_2_minus_128::ks_pbs::V1_3_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use current_params::list_compression::p_fail_2_minus_128::{
    V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use current_params::list_compression::p_fail_2_minus_64::{
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
};
use current_params::multi_bit::gaussian::p_fail_2_minus_128::ks_pbs_gpu::{
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
};
use current_params::multi_bit::gaussian::p_fail_2_minus_64::ks_pbs_gpu::{
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
};
use current_params::multi_bit::tuniform::p_fail_2_minus_128::ks_pbs_gpu::{
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
};
use current_params::multi_bit::tuniform::p_fail_2_minus_64::ks_pbs_gpu::{
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
};
use current_params::noise_squashing::p_fail_2_minus_128::V1_3_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

use super::current_params::{
    V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_3_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use super::NoiseSquashingCompressionParameters;
use crate::shortint::parameters::noise_squashing::NoiseSquashingMultiBitParameters;

// Aliases

// Compute Gaussian
// 2M128
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

// Used by CRT doctests
pub const PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128: ClassicPBSParameters =
    V1_3_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;

// 2M64
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: ClassicPBSParameters =
    V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

// Compute TUniform
// 2M128
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS: ClassicPBSParameters =
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_MESSAGE_2_CARRY_2: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

// 2M64
pub const PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: ClassicPBSParameters =
    V1_3_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

// Compression Gaussian
// 2M128
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: CompressionParameters =
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

// 2M64
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;

// Compression TUniform
// 2M128
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters =
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompressionParameters =
    V1_3_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS: CompressionParameters =
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_MESSAGE_2_CARRY_2: CompressionParameters = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

// 2M64
pub const COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    V1_3_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

// PKE TUniform
pub const PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompactPublicKeyEncryptionParameters =
    V1_3_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// PKE To Compute Keyswitch
pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ShortintKeySwitchingParameters =
    V1_3_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// Noise squashing
pub const NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: NoiseSquashingParameters =
    V1_3_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// Noise squashing compression
pub const NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingCompressionParameters =
    V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters =
    V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingMultiBitParameters =
    V1_3_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// GPU 2^-64
// GPU TUniform
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64;

// GPU Gaussian
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64;

// GPU 2^-128
// GPU TUniform
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;

pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

pub const COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS: CompressionParameters =
    COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

// GPU Gaussian
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
pub const PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128:
    MultiBitPBSParameters =
    V1_3_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;

// GPU PKE To Compute Keyswitch
pub const PARAM_GPU_MULTI_BIT_GROUP_4_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    ShortintKeySwitchingParameters =
    V1_3_PARAM_MULTI_BIT_GROUP_4_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
