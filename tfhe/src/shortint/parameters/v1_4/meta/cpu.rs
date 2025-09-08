use super::super::super::meta::{DedicatedCompactPublicKeyParameters, MetaParameters};
use super::super::classic::compact_pk::gaussian::p_fail_2_minus_128::ks_pbs::*;
use super::super::classic::compact_pk::gaussian::p_fail_2_minus_128::pbs_ks::*;
use super::super::classic::compact_pk::gaussian::p_fail_2_minus_64::ks_pbs::*;
use super::super::classic::compact_pk::gaussian::p_fail_2_minus_64::pbs_ks::*;
use super::super::classic::gaussian::p_fail_2_minus_128::ks_pbs::*;
use super::super::classic::gaussian::p_fail_2_minus_128::pbs_ks::*;
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
use crate::shortint::parameters::{Backend, MetaNoiseSquashingParameters};
use crate::shortint::{AtomicPatternParameters, PBSParameters};

pub const V1_4_META_PARAM_CPU_1_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_6_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_7_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_6_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_8_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_PBS_KS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_PBS_KS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_PBS_KS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_PBS_KS_COMPACT_PK_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_6_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_7_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_6_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_5_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_3_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_2_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_1_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_8_0_KS_PBS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_1_PBS_KS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_2_PBS_KS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_3_PBS_KS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_4_PBS_KS_COMPACT_PK_GAUSSIAN_2M128: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
            V1_4_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

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

pub const V1_4_META_PARAM_CPU_1_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M128,
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

pub const V1_4_META_PARAM_CPU_1_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_3_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_4_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_5_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_6_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_7_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M128,
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

pub const V1_4_META_PARAM_CPU_2_3_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_4_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_5_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_6_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
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

pub const V1_4_META_PARAM_CPU_3_4_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_5_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_3_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M128,
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

pub const V1_4_META_PARAM_CPU_5_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_5_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_5_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_5_3_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_6_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_6_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_6_2_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_7_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_7_1_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_8_0_KS_PBS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_1_1_PBS_KS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_2_2_PBS_KS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_3_3_PBS_KS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M128,
    )),
    dedicated_compact_public_key_parameters: None,
    compression_parameters: None,
    noise_squashing_parameters: None,
};

pub const V1_4_META_PARAM_CPU_4_4_PBS_KS_GAUSSIAN_2M128: MetaParameters = MetaParameters {
    backend: Backend::Cpu,
    compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
        V1_4_PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M128,
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

pub const V1_4_META_PARAM_CPU_1_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_1_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_5_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_6_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_7_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_2_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_5_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_6_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_3_4_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_5_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_5_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_3_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_2_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_1_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_8_0_MULTI_BIT_GROUP_2_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_2_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_1_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_5_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_6_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_7_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_2_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_5_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_6_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_3_4_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_5_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_5_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_3_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_2_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_1_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_8_0_MULTI_BIT_GROUP_3_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_3_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_1_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_5_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_6_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_1_7_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_2_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_5_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_2_6_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_3_4_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_3_5_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_4_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
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

pub const V1_4_META_PARAM_CPU_5_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_5_3_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_6_2_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_7_1_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64,
        )),
        dedicated_compact_public_key_parameters: None,
        compression_parameters: None,
        noise_squashing_parameters: None,
    };

pub const V1_4_META_PARAM_CPU_8_0_MULTI_BIT_GROUP_4_KS_PBS_GAUSSIAN_2M64: MetaParameters =
    MetaParameters {
        backend: Backend::Cpu,
        compute_parameters: AtomicPatternParameters::Standard(PBSParameters::MultiBitPBS(
            V1_4_PARAM_MULTI_BIT_GROUP_4_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64,
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
        }),
        compression_parameters: Some(V1_4_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        noise_squashing_parameters: Some(MetaNoiseSquashingParameters {
            parameters: V1_4_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            compression_parameters: Some(
                V1_4_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        }),
    };
