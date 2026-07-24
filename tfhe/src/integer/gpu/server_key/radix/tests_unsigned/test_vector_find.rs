use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_contains_clear_test_case, default_contains_test_case,
    default_first_index_in_clears_test_case, default_first_index_of_clear_test_case,
    default_first_index_of_test_case, default_index_in_clears_test_case,
    default_index_of_clear_test_case, default_index_of_test_case, default_is_in_clears_test_case,
    default_match_value_or_test_case, default_match_value_test_case,
    unchecked_contains_clear_test_case, unchecked_contains_test_case,
    unchecked_first_index_in_clears_test_case, unchecked_first_index_of_clear_test_case,
    unchecked_first_index_of_test_case, unchecked_index_in_clears_test_case,
    unchecked_index_of_clear_test_case, unchecked_index_of_test_case,
    unchecked_is_in_clears_test_case, unchecked_match_value_or_test_case,
    unchecked_match_value_test_case,
};

use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_match_value);
create_gpu_parameterized_test!(integer_unchecked_match_value_or);
create_gpu_parameterized_test!(integer_unchecked_contains);
create_gpu_parameterized_test!(integer_unchecked_contains_clear);
create_gpu_parameterized_test!(integer_unchecked_is_in_clears);
create_gpu_parameterized_test!(integer_unchecked_index_in_clears);
create_gpu_parameterized_test!(integer_unchecked_first_index_in_clears);
create_gpu_parameterized_test!(integer_unchecked_index_of);
create_gpu_parameterized_test!(integer_unchecked_index_of_clear);
create_gpu_parameterized_test!(integer_unchecked_first_index_of);
create_gpu_parameterized_test!(integer_unchecked_first_index_of_clear);

create_gpu_parameterized_test!(integer_default_match_value);
create_gpu_parameterized_test!(integer_default_match_value_or);
create_gpu_parameterized_test!(integer_default_contains);
create_gpu_parameterized_test!(integer_default_contains_clear);
create_gpu_parameterized_test!(integer_default_is_in_clears);
create_gpu_parameterized_test!(integer_default_index_in_clears);
create_gpu_parameterized_test!(integer_default_first_index_in_clears);
create_gpu_parameterized_test!(integer_default_index_of);
create_gpu_parameterized_test!(integer_default_index_of_clear);
create_gpu_parameterized_test!(integer_default_first_index_of);
create_gpu_parameterized_test!(integer_default_first_index_of_clear);

fn integer_unchecked_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_match_value);
    unchecked_match_value_test_case(param, executor);
}

fn integer_unchecked_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_match_value_or);
    unchecked_match_value_or_test_case(param, executor);
}

fn integer_unchecked_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_contains);
    unchecked_contains_test_case(param, executor);
}

fn integer_unchecked_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_contains_clear);
    unchecked_contains_clear_test_case(param, executor);
}

fn integer_unchecked_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_is_in_clears);
    unchecked_is_in_clears_test_case(param, executor);
}

fn integer_unchecked_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_in_clears);
    unchecked_index_in_clears_test_case(param, executor);
}

fn integer_unchecked_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_in_clears);
    unchecked_first_index_in_clears_test_case(param, executor);
}
fn integer_unchecked_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_of);
    unchecked_index_of_test_case(param, executor);
}

fn integer_unchecked_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_index_of_clear);
    unchecked_index_of_clear_test_case(param, executor);
}

fn integer_unchecked_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_of_clear);
    unchecked_first_index_of_clear_test_case(param, executor);
}

fn integer_unchecked_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_first_index_of);
    unchecked_first_index_of_test_case(param, executor);
}

// Default tests

fn integer_default_match_value<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::match_value);
    default_match_value_test_case(param, executor);
}

fn integer_default_match_value_or<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::match_value_or);
    default_match_value_or_test_case(param, executor);
}

fn integer_default_contains<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::contains);
    default_contains_test_case(param, executor);
}

fn integer_default_contains_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::contains_clear);
    default_contains_clear_test_case(param, executor);
}

fn integer_default_is_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::is_in_clears);
    default_is_in_clears_test_case(param, executor);
}

fn integer_default_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_in_clears);
    default_index_in_clears_test_case(param, executor);
}

fn integer_default_first_index_in_clears<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_in_clears);
    default_first_index_in_clears_test_case(param, executor);
}

fn integer_default_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_of);
    default_index_of_test_case(param, executor);
}

fn integer_default_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::index_of_clear);
    default_index_of_clear_test_case(param, executor);
}

fn integer_default_first_index_of<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_of);
    default_first_index_of_test_case(param, executor);
}

fn integer_default_first_index_of_clear<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::first_index_of_clear);
    default_first_index_of_clear_test_case(param, executor);
}

/// Checks that an input list mixing ciphertexts from several GPUs panics
/// cleanly instead of causing an illegal memory access.
#[test]
fn test_gpu_integer_contains_rejects_mixed_gpu_inputs() {
    if get_number_of_gpus() < 2 {
        println!("skipping mixed-GPU input test: fewer than 2 GPUs visible");
        return;
    }

    let streams0 = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let streams1 = CudaStreams::new_single_gpu(GpuIndex::new(1));
    let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams0);

    let num_blocks = 4;
    let d_value = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.encrypt_radix(3u32, num_blocks),
        &streams0,
    );

    let mut cts: Vec<CudaUnsignedRadixCiphertext> = (0..3u32)
        .map(|m| {
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &cks.encrypt_radix(m, num_blocks),
                &streams0,
            )
        })
        .collect();
    // This input lives on GPU 1 while the computation runs on GPU 0
    cts.push(CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.encrypt_radix(3u32, num_blocks),
        &streams1,
    ));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sks.unchecked_contains(&cts, &d_value, &streams0)
    }));
    assert!(
        result.is_err(),
        "contains must reject an input list mixing ciphertexts from several GPUs"
    );
}
