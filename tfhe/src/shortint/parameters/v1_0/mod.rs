//! FHE Parameters as they were defined in TFHE-rs 1.0.
//!
//! These parameters may be used for backward compatibility.

pub mod classic;
pub mod compact_public_key_only;
pub mod key_switching;
pub mod list_compression;
pub mod multi_bit;

pub use classic::compact_pk::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use classic::compact_pk::gaussian::p_fail_2_minus_64::pbs_ks::*;
pub use classic::gaussian::p_fail_2_minus_128::ks_pbs::*;
pub use classic::gaussian::p_fail_2_minus_128::pbs_ks::*;
pub use classic::tuniform::p_fail_2_minus_128::ks_pbs::*;
pub use compact_public_key_only::p_fail_2_minus_128::ks_pbs::*;
pub use key_switching::p_fail_2_minus_128::ks_pbs::*;
pub use list_compression::p_fail_2_minus_128::*;
pub use multi_bit::gaussian::p_fail_2_minus_64::ks_pbs::*;
pub use multi_bit::gaussian::p_fail_2_minus_64::ks_pbs_gpu::*;
pub use multi_bit::tuniform::p_fail_2_minus_64::ks_pbs::*;
pub use multi_bit::tuniform::p_fail_2_minus_64::ks_pbs_gpu::*;

use crate::shortint::parameters::classic::ClassicPBSParameters;

/// Vector containing all [`ClassicPBSParameters`] parameter sets
pub const ALL_PARAMETER_VEC: [ClassicPBSParameters; 29] = WITH_CARRY_PARAMETERS_VEC;

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const WITH_CARRY_PARAMETERS_VEC: [ClassicPBSParameters; 29] = [
    V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M128,
];

/// Vector containing all parameter sets where the carry space is strictly greater than one
pub const BIVARIATE_PBS_COMPLIANT_PARAMETER_SET_VEC: [ClassicPBSParameters; 17] = [
    V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M128,
    V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M128,
];
