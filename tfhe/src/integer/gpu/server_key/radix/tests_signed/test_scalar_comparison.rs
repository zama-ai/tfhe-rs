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

/// Parity with the CPU implementation for signed scalar min/max when the
/// scalar is out of the ciphertext's range or is an in-range negative value of
/// a wider clear type (whose early-stopping decomposition is sign-extended and
/// previously tripped the backend's block-count assert).
fn integer_signed_scalar_minmax_out_of_range<P>(param: P)
where
    P: Into<TestParameters>,
{
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaSignedRadixCiphertext;

    let cks = crate::integer::ClientKey::new(param.into());
    let streams = CudaStreams::new_multi_gpu();
    let cpu_sks = crate::integer::ServerKey::new_radix_server_key(&cks);
    let gpu_sks = CudaServerKey::new(&cks, &streams);

    let num_blocks = 4usize;
    let msg_mod = cks.parameters().message_modulus().0;
    let half = (msg_mod.pow(num_blocks as u32) / 2) as i64;
    let ct_max = half - 1; // max value of the type
    let ct_min = -half; // min value of the type

    let clears = [ct_min, -1i64, 0, ct_max];
    let scalars = [
        0i64,
        -1, // in range, but decomposes into a full-width block sequence
        ct_max,
        ct_min,
        ct_max + 1,
        ct_min - 1,
        i64::MAX,
        i64::MIN,
    ];

    for clear in clears {
        let ct = cks.encrypt_signed_radix(clear, num_blocks);
        let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &streams);
        for scalar in scalars {
            let results = [
                (
                    "unchecked_scalar_max",
                    cpu_sks.unchecked_scalar_max_parallelized(&ct, scalar),
                    gpu_sks.unchecked_scalar_max(&d_ct, scalar, &streams),
                ),
                (
                    "unchecked_scalar_min",
                    cpu_sks.unchecked_scalar_min_parallelized(&ct, scalar),
                    gpu_sks.unchecked_scalar_min(&d_ct, scalar, &streams),
                ),
                (
                    "scalar_max",
                    cpu_sks.scalar_max_parallelized(&ct, scalar),
                    gpu_sks.scalar_max(&d_ct, scalar, &streams),
                ),
                (
                    "scalar_min",
                    cpu_sks.scalar_min_parallelized(&ct, scalar),
                    gpu_sks.scalar_min(&d_ct, scalar, &streams),
                ),
            ];
            for (name, cpu_res, gpu_res) in results {
                let cpu_dec: i64 = cks.decrypt_signed_radix(&cpu_res);
                let gpu_dec: i64 =
                    cks.decrypt_signed_radix(&gpu_res.to_signed_radix_ciphertext(&streams));
                assert_eq!(
                    cpu_dec, gpu_dec,
                    "CPU and GPU {name} differ for ct {clear} vs scalar {scalar}: \
                     CPU {cpu_dec}, GPU {gpu_dec}"
                );
            }
        }
    }
}

create_gpu_parameterized_test!(integer_signed_scalar_minmax_out_of_range {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
