use crate::shortint::parameters::KeySwitch32PBSParameters;

// p-fail = 2^-129.358, algorithmic cost ~ 113, 2-norm = 5
// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000140546154228955)
pub const V1_4_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128: KeySwitch32PBSParameters =
    crate::shortint::parameters::v1_3::V1_3_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
