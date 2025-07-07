use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_comparison::{
    test_signed_default_scalar_function, test_signed_default_scalar_minmax,
    test_signed_unchecked_scalar_function, test_signed_unchecked_scalar_minmax,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

/// This macro generates the tests for a given comparison fn
///
/// All our comparison function have 2 variants:
/// - unchecked_$comparison_name
/// - $comparison_name
///
/// So, for example, for the `gt` comparison fn, this macro will generate the tests for
/// the 2 variants described above
macro_rules! define_gpu_signed_scalar_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_signed_unchecked_scalar_ $comparison_name _ $clear_type>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<unchecked_scalar_ $comparison_name>]);
                test_signed_unchecked_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_signed_default_scalar_ $comparison_name $clear_type>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 10;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<scalar_ $comparison_name>]);
                test_signed_default_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_gpu_parameterized_test!([<integer_signed_unchecked_scalar_ $comparison_name _ $clear_type>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            });
            create_gpu_parameterized_test!([<integer_signed_default_scalar_ $comparison_name $clear_type>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            });
        }
    };
}

fn integer_signed_unchecked_scalar_min_i128<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_min);
    test_signed_unchecked_scalar_minmax(params, 2, executor, std::cmp::min::<i128>);
}

fn integer_signed_unchecked_scalar_max_i128<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_max);
    test_signed_unchecked_scalar_minmax(params, 2, executor, std::cmp::max::<i128>);
}

fn integer_signed_scalar_min_i128<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_min);
    test_signed_default_scalar_minmax(params, 2, executor, std::cmp::min::<i128>);
}

fn integer_signed_scalar_max_i128<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_max);
    test_signed_default_scalar_minmax(params, 2, executor, std::cmp::max::<i128>);
}

create_gpu_parameterized_test!(integer_signed_unchecked_scalar_max_i128 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_unchecked_scalar_min_i128 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_scalar_max_i128 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_scalar_min_i128 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

define_gpu_signed_scalar_comparison_test_functions!(eq, i128);
define_gpu_signed_scalar_comparison_test_functions!(ne, i128);
define_gpu_signed_scalar_comparison_test_functions!(lt, i128);
define_gpu_signed_scalar_comparison_test_functions!(le, i128);
define_gpu_signed_scalar_comparison_test_functions!(gt, i128);
define_gpu_signed_scalar_comparison_test_functions!(ge, i128);
