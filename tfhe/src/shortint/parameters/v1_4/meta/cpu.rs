use super::super::super::meta::{DedicatedCompactPublicKeyParameters, MetaParameters};
use super::super::classic::gaussian::p_fail_2_minus_128::ks_pbs::*;
use super::super::classic::gaussian::p_fail_2_minus_40::ks_pbs::*;
use super::super::classic::gaussian::p_fail_2_minus_64::ks_pbs::*;
use super::super::classic::tuniform::p_fail_2_minus_128::ks_pbs::*;
use super::super::classic::tuniform::p_fail_2_minus_40::ks_pbs::*;
use super::super::classic::tuniform::p_fail_2_minus_64::ks_pbs::*;
use super::super::compact_public_key_only::p_fail_2_minus_128::ks_pbs::*;
use super::super::key_switching::p_fail_2_minus_128::ks_pbs::*;
use super::super::ks32::tuniform::p_fail_2_minus_128::ks_pbs::*;
use super::super::list_compression::p_fail_2_minus_128::*;
use super::super::list_compression::p_fail_2_minus_64::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_128::ks_pbs::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_40::ks_pbs::*;
use super::super::multi_bit::gaussian::p_fail_2_minus_64::ks_pbs::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_128::ks_pbs::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_40::ks_pbs::*;
use super::super::multi_bit::tuniform::p_fail_2_minus_64::ks_pbs::*;
use super::super::noise_squashing::p_fail_2_minus_128::*;
use crate::shortint::parameters::{
    Backend, MetaNoiseSquashingParameters, ReRandomizationParameters,
};
use crate::shortint::{AtomicPatternParameters, PBSParameters};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_GAUSSIAN_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_GAUSSIAN_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_GAUSSIAN_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_GAUSSIAN_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64),
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_GAUSSIAN_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_GAUSSIAN_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128),
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_TUNIFORM_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_TUNIFORM_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_TUNIFORM_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_TUNIFORM_2M40: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_TUNIFORM_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_TUNIFORM_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64),
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_TUNIFORM_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_TUNIFORM_2M64: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_TUNIFORM_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_TUNIFORM_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_TUNIFORM_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M40: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_2_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_3_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_MULTI_BIT_GROUP_4_KS_PBS_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_KS32_PBS_TUNIFORM_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::KeySwitch32(
        V1_4_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    ),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };

pub const V1_4_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::KeySwitch32(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        ),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };

pub const V1_4_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::KeySwitch32(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        ),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV1_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_BIG_ZKV1_TUNIFORM_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        dedicated_compact_public_key_parameters: Some(DedicatedCompactPublicKeyParameters {
            pke_params: V1_4_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            ksk_params:
                V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
            re_randomization_parameters: Some(
                ReRandomizationParameters::DedicatedCompactPublicKeyWithKeySwitch {
                    re_rand_ksk_params:
                        V1_4_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
                },
            ),
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };
