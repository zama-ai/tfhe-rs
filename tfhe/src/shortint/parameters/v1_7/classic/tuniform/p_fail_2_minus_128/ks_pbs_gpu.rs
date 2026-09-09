use crate::shortint::parameters::ClassicPBSParameters;
/// p-fail = 2^-144.851, algorithmic cost ~ 93.2, 2-norm = 3
#[deprecated(
    since = "1.7.1",
    note = "This parameter set has lower pfail than expected, upgrade to 1.8+ for a replacement"
)]
#[allow(deprecated)]
pub const V1_7_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_6::V1_6_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
