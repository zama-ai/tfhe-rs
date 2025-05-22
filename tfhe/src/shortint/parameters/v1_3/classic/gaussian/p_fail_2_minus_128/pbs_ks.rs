use crate::shortint::parameters::ClassicPBSParameters;
/// p-fail = 2^-128.181, algorithmic cost ~ 70, 2-norm = 3
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.0000226994502138943)
pub const V1_3_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_1_CARRY_1_PBS_KS_GAUSSIAN_2M128;
/// p-fail = 2^-128.163, algorithmic cost ~ 128, 2-norm = 5
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000141892645707080)
pub const V1_3_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128;
/// p-fail = 2^-128.674, algorithmic cost ~ 2030, 2-norm = 9
/// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(8.83211431719384E-8)
pub const V1_3_PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_3_CARRY_3_PBS_KS_GAUSSIAN_2M128;
/// p-fail = 2^-129.799, algorithmic cost ~ 13785, 2-norm = 17
/// Average number of encryptions of 0s ~ 34, peak noise ~ Variance(5.47094548750703E-9)
pub const V1_3_PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_1::V1_1_PARAM_MESSAGE_4_CARRY_4_PBS_KS_GAUSSIAN_2M128;
