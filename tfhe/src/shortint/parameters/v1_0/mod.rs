//! FHE Parameters as they were defined in TFHE-rs 1.0.
//!
//! These parameters may be used for backward compatibility.

pub mod classic;
pub mod compact_public_key_only;
pub mod key_switching;
pub mod list_compression;
pub mod multi_bit;

pub use classic::compact_pk::gaussian::p_fail_2_minus_128::ks_pbs::*;
pub use classic::compact_pk::gaussian::p_fail_2_minus_128::pbs_ks::*;
pub use classic::compact_pk::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use classic::compact_pk::gaussian::p_fail_2_minus_64::pbs_ks::*;
pub use classic::gaussian::p_fail_2_minus_128::ks_pbs::*;
pub use classic::gaussian::p_fail_2_minus_128::pbs_ks::*;
pub use classic::gaussian::p_fail_2_minus_40::ks_pbs::*;
pub use classic::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use classic::tuniform::p_fail_2_minus_128::ks_pbs::*;
pub use classic::tuniform::p_fail_2_minus_40::ks_pbs::*;
pub use classic::tuniform::p_fail_2_minus_64::ks_pbs::*;
pub use compact_public_key_only::p_fail_2_minus_128::ks_pbs::*;
pub use key_switching::p_fail_2_minus_128::ks_pbs::*;
pub use list_compression::p_fail_2_minus_128::*;
pub use multi_bit::gaussian::p_fail_2_minus_128::ks_pbs::*;
pub use multi_bit::gaussian::p_fail_2_minus_128::ks_pbs_gpu::*;
pub use multi_bit::gaussian::p_fail_2_minus_40::ks_pbs::*;
pub use multi_bit::gaussian::p_fail_2_minus_40::ks_pbs_gpu::*;
pub use multi_bit::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use multi_bit::gaussian::p_fail_2_minus_64::ks_pbs_gpu::*;
pub use multi_bit::tuniform::p_fail_2_minus_128::ks_pbs::*;
pub use multi_bit::tuniform::p_fail_2_minus_128::ks_pbs_gpu::*;
pub use multi_bit::tuniform::p_fail_2_minus_40::ks_pbs::*;
pub use multi_bit::tuniform::p_fail_2_minus_40::ks_pbs_gpu::*;
pub use multi_bit::tuniform::p_fail_2_minus_64::ks_pbs::*;
pub use multi_bit::tuniform::p_fail_2_minus_64::ks_pbs_gpu::*;

use crate::shortint::parameters::{ClassicPBSParameters, MultiBitPBSParameters};

/// All [`ClassicPBSParameters`] in this module.
pub const VEC_ALL_CLASSIC_PARAMETERS: [&ClassicPBSParameters; 1] =
    [&V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128];

/// All [`MultiBitPBSParameters`] in this module.
pub const VEC_ALL_MULTI_BIT_PARAMETERS: [&MultiBitPBSParameters; 1] =
    [&V1_0_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64];
