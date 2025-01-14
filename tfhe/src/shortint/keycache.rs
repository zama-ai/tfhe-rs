use std::sync::LazyLock;

use crate::keycache::utils::named_params_impl;
use crate::keycache::*;
use crate::shortint::parameters::classic::compact_pk::*;
use crate::shortint::parameters::classic::tuniform::p_fail_2_minus_64::ks_pbs::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use crate::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS;
use crate::shortint::parameters::key_switching::*;
use crate::shortint::parameters::list_compression::*;
use crate::shortint::parameters::multi_bit::tuniform::p_fail_2_minus_64::ks_pbs::{
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
};
use crate::shortint::parameters::parameters_wopbs::*;
use crate::shortint::parameters::*;
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{ClientKey, KeySwitchingKey, ServerKey};
use serde::{Deserialize, Serialize};

named_params_impl!( ShortintParameterSet =>
    V0_11_PARAM_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    // Small
    V0_11_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M64,
    // MultiBit Group 2
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    // MultiBit Group 3
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    // CPU Multibit TUniform
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M64,
    // MultiBit Group 3 GPU
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    // GPU MultiBit Group 2
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    // GPU MultiBit Group 4
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    V1_0_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M64,
    // CPK
    V0_11_PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
    // CPK SMALL
    V0_11_PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
    V0_11_PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
    // TUniform
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
    // Wopbs
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    // Wopbs only
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    // Coverage
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
    #[cfg(tarpaulin)]
    COVERAGE_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
);

impl NamedParam for ClassicPBSParameters {
    fn name(&self) -> String {
        PBSParameters::from(*self).name()
    }
}

impl NamedParam for MultiBitPBSParameters {
    fn name(&self) -> String {
        PBSParameters::from(*self).name()
    }
}

impl NamedParam for PBSParameters {
    fn name(&self) -> String {
        ShortintParameterSet::from(*self).name()
    }
}

impl NamedParam for WopbsParameters {
    fn name(&self) -> String {
        ShortintParameterSet::from(*self).name()
    }
}

impl NamedParam for ShortintKeySwitchingParameters {
    fn name(&self) -> String {
        named_params_impl!(expose V0_11_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS);
        named_params_impl!(
            {
                *self;
                Self
            } == (V0_11_PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS)
        );

        format!(
            "PARAM_KEYSWITCH_CUSTOM_KS_LEVEL_{}_KS_BASE_LOG_{}",
            self.ks_level.0, self.ks_base_log.0
        )
    }
}

impl NamedParam for CompressionParameters {
    fn name(&self) -> String {
        named_params_impl!(expose
            COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
        );

        named_params_impl!(
            {
                *self;
                Self
            } == (COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        );

        format!(
            "COMP_PARAM_CUSTOM_BR_LEVEL_{}_NOISE_DISTRIB_{}",
            self.br_level.0, self.packing_ks_key_noise_distribution
        )
    }
}

impl NamedParam for CompactPublicKeyEncryptionParameters {
    fn name(&self) -> String {
        named_params_impl!(expose
            V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
        );

        named_params_impl!(
            {
                *self;
                Self
            } == (V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        );

        format!(
            "CPKE_PARAM_CUSTOM_LWE_DIM_{}_NOISE_DISTRIB_{}",
            self.encryption_lwe_dimension.0, self.encryption_noise_distribution
        )
    }
}

impl From<PBSParameters> for (ClientKey, ServerKey) {
    fn from(param: PBSParameters) -> Self {
        let param_set = ShortintParameterSet::from(param);
        param_set.into()
    }
}

impl From<ShortintParameterSet> for (ClientKey, ServerKey) {
    fn from(param: ShortintParameterSet) -> Self {
        let cks = ClientKey::new(param);
        let sks = ServerKey::new(&cks);
        (cks, sks)
    }
}

pub struct Keycache {
    inner: ImplKeyCache<PBSParameters, (ClientKey, ServerKey), FileStorage>,
}

impl Default for Keycache {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/shortint/client_server".to_string(),
            )),
        }
    }
}

pub struct SharedKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
}

pub struct SharedWopbsKey {
    inner: GenericSharedKey<(ClientKey, ServerKey)>,
    wopbs: GenericSharedKey<WopbsKey>,
}

pub struct SharedKeySwitchingKey {
    inner_1: GenericSharedKey<(ClientKey, ServerKey)>,
    inner_2: GenericSharedKey<(ClientKey, ServerKey)>,
    ksk: GenericSharedKey<KeySwitchingKey>,
}

impl SharedKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
}

impl SharedWopbsKey {
    pub fn client_key(&self) -> &ClientKey {
        &self.inner.0
    }
    pub fn server_key(&self) -> &ServerKey {
        &self.inner.1
    }
    pub fn wopbs_key(&self) -> &WopbsKey {
        &self.wopbs
    }
}

impl SharedKeySwitchingKey {
    pub fn client_key_1(&self) -> &ClientKey {
        &self.inner_1.0
    }
    pub fn server_key_1(&self) -> &ServerKey {
        &self.inner_1.1
    }
    pub fn client_key_2(&self) -> &ClientKey {
        &self.inner_2.0
    }
    pub fn server_key_2(&self) -> &ServerKey {
        &self.inner_2.1
    }
    pub fn key_switching_key(&self) -> &KeySwitchingKey {
        &self.ksk
    }
}

impl Keycache {
    pub fn get_from_param<P>(&self, param: P) -> SharedKey
    where
        P: Into<PBSParameters>,
    {
        SharedKey {
            inner: self.inner.get(param.into()),
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[cfg(feature = "experimental")]
mod wopbs {
    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct WopbsParamPair(pub PBSParameters, pub WopbsParameters);

    impl<P> From<(P, WopbsParameters)> for WopbsParamPair
    where
        P: Into<PBSParameters>,
    {
        fn from(tuple: (P, WopbsParameters)) -> Self {
            Self(tuple.0.into(), tuple.1)
        }
    }

    impl NamedParam for WopbsParamPair {
        fn name(&self) -> String {
            self.1.name()
        }
    }

    /// The KeyCache struct for shortint.
    ///
    /// You should not create an instance yourself,
    /// but rather use the global variable defined: [static@KEY_CACHE_WOPBS]
    pub struct KeycacheWopbsV0 {
        inner: ImplKeyCache<WopbsParamPair, WopbsKey, FileStorage>,
    }

    impl Default for KeycacheWopbsV0 {
        fn default() -> Self {
            Self {
                inner: ImplKeyCache::new(FileStorage::new("../keys/shortint/wopbs_v0".to_string())),
            }
        }
    }

    impl KeycacheWopbsV0 {
        pub fn get_from_param<T: Into<WopbsParamPair>>(&self, params: T) -> SharedWopbsKey {
            let params = params.into();
            let key = KEY_CACHE.get_from_param(params.0);
            let wk = self.inner.get_with_closure(params, &mut |_| {
                WopbsKey::new_wopbs_key(&key.inner.0, &key.inner.1, &params.1)
            });
            SharedWopbsKey {
                inner: key.inner,
                wopbs: wk,
            }
        }

        pub fn clear_in_memory_cache(&self) {
            self.inner.clear_in_memory_cache();
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKeyParams(
    pub PBSParameters,
    pub PBSParameters,
    pub ShortintKeySwitchingParameters,
);

impl<P> From<(P, P, ShortintKeySwitchingParameters)> for KeySwitchingKeyParams
where
    P: Into<PBSParameters>,
{
    fn from(tuple: (P, P, ShortintKeySwitchingParameters)) -> Self {
        Self(tuple.0.into(), tuple.1.into(), tuple.2)
    }
}

impl NamedParam for KeySwitchingKeyParams {
    fn name(&self) -> String {
        format!("{}__{}__{}", self.0.name(), self.1.name(), self.2.name())
    }
}

/// The KeyCache struct for shortint.
///
/// You should not create an instance yourself,
/// but rather use the global variable defined: [static@KEY_CACHE_KSK]
pub struct KeycacheKeySwitchingKey {
    inner: ImplKeyCache<KeySwitchingKeyParams, KeySwitchingKey, FileStorage>,
}

impl Default for KeycacheKeySwitchingKey {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new("../keys/shortint/ksk".to_string())),
        }
    }
}

impl KeycacheKeySwitchingKey {
    pub fn get_from_param<T: Into<KeySwitchingKeyParams>>(
        &self,
        params: T,
    ) -> SharedKeySwitchingKey {
        let params = params.into();
        let key_1 = KEY_CACHE.get_from_param(params.0);
        let key_2 = KEY_CACHE.get_from_param(params.1);
        let ksk = self.inner.get_with_closure(params, &mut |_| {
            KeySwitchingKey::new(
                (key_1.client_key(), Some(key_1.server_key())),
                (key_2.client_key(), key_2.server_key()),
                params.2,
            )
        });
        SharedKeySwitchingKey {
            inner_1: key_1.inner,
            inner_2: key_2.inner,
            ksk,
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

pub static KEY_CACHE: LazyLock<Keycache> = LazyLock::new(Keycache::default);
pub static KEY_CACHE_KSK: LazyLock<KeycacheKeySwitchingKey> =
    LazyLock::new(KeycacheKeySwitchingKey::default);

#[cfg(feature = "experimental")]
pub static KEY_CACHE_WOPBS: LazyLock<wopbs::KeycacheWopbsV0> =
    LazyLock::new(wopbs::KeycacheWopbsV0::default);
