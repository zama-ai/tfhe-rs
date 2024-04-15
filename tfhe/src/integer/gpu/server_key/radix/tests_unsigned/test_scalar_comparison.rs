use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_scalar_comparison::{
    test_default_scalar_function, test_default_scalar_minmax, test_unchecked_scalar_function,
    test_unchecked_scalar_minmax,
};
use crate::integer::U256;
use crate::shortint::parameters::*;
use rand::Rng;
/// This macro generates the tests for a given scalar comparison fn
///
/// All our comparison function have 2 variants:
/// - unchecked_$comparison_name
/// - $comparison_name
///
/// So, for example, for the `gt` comparison fn, this macro will generate the tests for
/// the 2 variants described above
macro_rules! define_gpu_scalar_comparison_test_functions {
    ($comparison_name:ident, $clear_type:ty) => {
        ::paste::paste!{
            fn [<integer_unchecked_scalar_ $comparison_name _ $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters>{
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<unchecked_scalar_ $comparison_name>]);
                test_unchecked_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            fn [<integer_default_scalar_ $comparison_name $clear_type:lower>]<P>(param: P) where P: Into<PBSParameters> {
                let num_tests = 1;
                let executor = GpuFunctionExecutor::new(&CudaServerKey::[<scalar_ $comparison_name>]);
                test_default_scalar_function(
                    param,
                    num_tests,
                    executor,
                    |lhs, rhs| $clear_type::from(<$clear_type>::$comparison_name(&lhs, &rhs)),
                )
            }

            create_gpu_parametrized_test!([<integer_unchecked_scalar_ $comparison_name _ $clear_type:lower>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            });
            create_gpu_parametrized_test!([<integer_default_scalar_ $comparison_name$clear_type:lower>]{
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            });
        }
    };
}

fn integer_unchecked_scalar_min_u256<P>(params: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::unchecked_scalar_min);
    test_unchecked_scalar_minmax(params, 2, executor, std::cmp::min::<U256>);
}

fn integer_unchecked_scalar_max_u256<P>(params: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::unchecked_scalar_max);
    test_unchecked_scalar_minmax(params, 2, executor, std::cmp::max::<U256>);
}

fn integer_scalar_min_u256<P>(params: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::scalar_min);
    test_default_scalar_minmax(params, 2, executor, std::cmp::min::<U256>);
}

fn integer_scalar_max_u256<P>(params: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(CudaServerKey::scalar_max);
    test_default_scalar_minmax(params, 2, executor, std::cmp::max::<U256>);
}

// The goal of this function is to ensure that scalar comparisons
// work when the scalar type used is either bigger or smaller (in bit size)
// compared to the ciphertext
fn integer_unchecked_scalar_comparisons_edge<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let p = param.into();
    let num_block = (128f64 / (p.message_modulus().0 as f64).log(2.0)).ceil() as usize;

    let stream = CudaStreams::new_multi_gpu();

    let (cks, sks) = gen_keys_gpu(p, &stream);

    let mut rng = rand::thread_rng();

    for _ in 0..4 {
        let clear_a = rng.gen_range((u128::from(u64::MAX) + 1)..=u128::MAX);
        let smaller_clear = rng.gen::<u64>();
        let bigger_clear = rng.gen::<U256>();

        let a = cks.encrypt_radix(clear_a, num_block);
        // Copy to the GPU
        let d_a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&a, &stream);

        // >=
        {
            let d_result = sks.unchecked_scalar_ge(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) >= U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_ge(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) >= bigger_clear);
        }

        // >
        {
            let d_result = sks.unchecked_scalar_gt(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) > U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_gt(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) > bigger_clear);
        }

        // <=
        {
            let d_result = sks.unchecked_scalar_le(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) <= U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_le(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) <= bigger_clear);
        }

        // <
        {
            let d_result = sks.unchecked_scalar_lt(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_lt(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < bigger_clear);
        }

        // ==
        {
            let d_result = sks.unchecked_scalar_eq(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_eq(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == bigger_clear);
        }

        // !=
        {
            let d_result = sks.unchecked_scalar_ne(&d_a, smaller_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != U256::from(smaller_clear));

            let d_result = sks.unchecked_scalar_ne(&d_a, bigger_clear, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != bigger_clear);
        }

        // Here the goal is to test, the branching
        // made in the scalar sign function
        //
        // We are forcing one of the two branches to work on empty slices
        {
            let d_result = sks.unchecked_scalar_lt(&d_a, U256::ZERO, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::ZERO);

            let d_result = sks.unchecked_scalar_lt(&d_a, U256::MAX, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) < U256::MAX);

            // == (as it does not share same code)
            let d_result = sks.unchecked_scalar_eq(&d_a, U256::ZERO, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) == U256::ZERO);

            // != (as it does not share same code)
            let d_result = sks.unchecked_scalar_ne(&d_a, U256::MAX, &stream);
            let result = d_result.to_boolean_block(&stream);
            let decrypted = cks.decrypt_bool(&result);
            assert_eq!(decrypted, U256::from(clear_a) != U256::MAX);
        }
    }
}

create_gpu_parametrized_test!(integer_unchecked_scalar_min_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
});
create_gpu_parametrized_test!(integer_unchecked_scalar_max_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
});
create_gpu_parametrized_test!(integer_scalar_min_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
});
create_gpu_parametrized_test!(integer_scalar_max_u256 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
});

define_gpu_scalar_comparison_test_functions!(eq, U256);
define_gpu_scalar_comparison_test_functions!(ne, U256);
define_gpu_scalar_comparison_test_functions!(lt, U256);
define_gpu_scalar_comparison_test_functions!(le, U256);
define_gpu_scalar_comparison_test_functions!(gt, U256);
define_gpu_scalar_comparison_test_functions!(ge, U256);

create_gpu_parametrized_test!(integer_unchecked_scalar_comparisons_edge);
