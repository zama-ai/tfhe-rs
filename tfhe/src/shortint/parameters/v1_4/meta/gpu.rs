use super::super::super::meta::MetaParameters;
use super::super::list_compression::p_fail_2_minus_128::*;
use super::super::list_compression::p_fail_2_minus_64::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_128::ks_pbs_gpu::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_40::ks_pbs_gpu::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_64::ks_pbs_gpu::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_128::ks_pbs_gpu::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_40::ks_pbs_gpu::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_64::ks_pbs_gpu::*;
use crate::shortint::parameters::Backend;
use crate::shortint::{AtomicPatternParameters, PBSParameters};

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: Some(
            V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        ),
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: Some(
            V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        ),
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: Some(
            V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        ),
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: Some(
            V1_4_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };

pub const V1_4_META_PARAM_GPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::CudaGpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
        re_randomization_parameters: None,
    };
