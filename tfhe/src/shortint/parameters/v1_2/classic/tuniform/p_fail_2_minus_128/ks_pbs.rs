use crate::shortint::parameters::ClassicPBSParameters;
/// p-fail = 2^-144.044, algorithmic cost ~ 67, 2-norm = 3
/// Average number of encryptions of 0s ~ 15, peak noise ~ Variance(0.0000201396668936698)
pub const V1_2_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-129.358, algorithmic cost ~ 113, 2-norm = 5
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000140546154228955)
pub const V1_2_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-128.771, algorithmic cost ~ 900, 2-norm = 9
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.82526029096167E-8)
pub const V1_2_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128;
/// p-fail = 2^-141.493, algorithmic cost ~ 11860, 2-norm = 17
/// Average number of encryptions of 0s ~ 31, peak noise ~ Variance(5.00776611824111E-9)
pub const V1_2_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128;
