use crate::core_crypto::gpu::get_number_of_gpus;
use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_comparison::{
    test_default_function, test_default_minmax, test_unchecked_function, test_unchecked_minmax,
};
use crate::integer::U256;
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
macro_rules! define_gpu_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_unchecked_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters>{
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<unchecked_ $comparison_name>]);
                test_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<$comparison_name>]);
                test_default_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<multi_device_integer_default_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<TestParameters> {
                let num_tests = 1;
                let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::[<$comparison_name>]);
                let num_gpus = get_number_of_gpus();
                if num_gpus > 1 {
                    test_default_function(
                        param,
                        num_tests,
                        executor,
                        |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                    )
                }
            }

            create_gpu_parameterized_test!([<integer_unchecked_ $comparison_name _ $clear_type:lower>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            });
            create_gpu_parameterized_test!([<integer_default_ $comparison_name _ $clear_type:lower>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            });
            create_gpu_parameterized_test!([<multi_device_integer_default_ $comparison_name _ $clear_type:lower>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            });
        }
    };
}

fn integer_unchecked_min_u256<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::unchecked_min);
    test_unchecked_minmax(params, 2, executor, std::cmp::min::<U256>);
}

fn integer_unchecked_max_u256<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::unchecked_max);
    test_unchecked_minmax(params, 2, executor, std::cmp::max::<U256>);
}

fn integer_min_u256<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::min);
    test_default_minmax(params, 2, executor, std::cmp::min::<U256>);
}

fn integer_max_u256<P>(params: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::max);
    test_default_minmax(params, 2, executor, std::cmp::max::<U256>);
}

create_gpu_parameterized_test!(integer_unchecked_min_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_unchecked_max_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_min_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_max_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

define_gpu_comparison_test_functions!(eq, U256);
define_gpu_comparison_test_functions!(ne, U256);
define_gpu_comparison_test_functions!(lt, U256);
define_gpu_comparison_test_functions!(le, U256);
define_gpu_comparison_test_functions!(gt, U256);
define_gpu_comparison_test_functions!(ge, U256);
