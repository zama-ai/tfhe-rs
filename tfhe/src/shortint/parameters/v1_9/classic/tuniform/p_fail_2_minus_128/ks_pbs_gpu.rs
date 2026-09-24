use crate::shortint::parameters::ClassicPBSParameters;
/// p-fail = 2^-144.851, algorithmic cost ~ 93.2, 2-norm = 3
pub const V1_9_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_8::V1_8_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
/// GPU FastKreyvium transciphering, classical (non-multibit) PBS variant.
///
/// Classical twin of `V1_9_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128`
/// (same crypto core, no grouping factor). Z4 single-bit-extraction encoding:
/// message_modulus 2, carry_modulus 1, Delta = q/4, as the FastKreyvium kernels require.
/// `Standard` modulus switch matches the multibit baseline so the classical-vs-multibit
/// benchmark stays apples-to-apples. `log2_p_fail` is the optimizer's gpu_kreyvium value.
pub const V1_9_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128: ClassicPBSParameters =
    crate::shortint::parameters::v1_8::V1_8_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128;
