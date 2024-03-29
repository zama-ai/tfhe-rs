use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_comparison::{
    test_signed_default_function, test_signed_unchecked_function,
};
use crate::shortint::parameters::*;

/// This macro generates the tests for a given comparison fn
///
/// All our comparison function have 2 variants:
/// - unchecked_$comparison_name
/// - $comparison_name
///
/// So, for example, for the `gt` comparison fn, this macro will generate the tests for
/// the 2 variants described above
macro_rules! define_gpu_signed_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_signed_unchecked_ $comparison_name _ $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<unchecked_ $comparison_name>]);
                test_signed_unchecked_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs) as $clear_type),
                )
            }

            fn [<integer_signed_default_ $comparison_name $clear_type>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<$comparison_name>]);
                test_signed_default_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| <i8>::from(<i8>::$comparison_name(&lhs, &rhs) as i8),
                )
            }


            // Then call our create_gpu_parametrized_test macro onto or specialized fns
            create_gpu_parametrized_test!([<integer_signed_unchecked_ $comparison_name _ $clear_type>]);
            create_gpu_parametrized_test!([<integer_signed_default_ $comparison_name $clear_type>]);
        }
    };
}

define_gpu_signed_comparison_test_functions!(eq, i128);
define_gpu_signed_comparison_test_functions!(ne, i128);
