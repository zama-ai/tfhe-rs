use crate::integer::gpu::server_key::radix::tests_long_run::test_signed_random_op_sequence::signed_random_op_sequence_generic;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::server_key::radix_parallel::tests_long_run::NB_TESTS_SHORT_RUN;
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(signed_random_op_sequence {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
fn signed_random_op_sequence<P>(param: P)
where
    P: Into<TestParameters> + Clone,
{
    signed_random_op_sequence_generic(param, NB_TESTS_SHORT_RUN);
}
