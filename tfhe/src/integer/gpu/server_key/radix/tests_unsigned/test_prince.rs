use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    prince_decrypt_kat_test, prince_encrypt_decrypt_random_test, prince_encrypt_kat_test,
};
use crate::integer::{IntegerKeyKind, RadixClientKey};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(integer_prince_encrypt_kat {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_prince_decrypt_kat {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_prince_encrypt_decrypt_random {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_prince_encrypt_kat_reused_keys {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_prince_decrypt_kat_reused_keys {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

// Known-answer tests from [BEK+20, Appendix B], run one KAT at a time and in
// batches of 2 inputs sharing the same key pair.
fn integer_prince_encrypt_kat<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::prince_encrypt);
    prince_encrypt_kat_test(param, executor);
}

fn integer_prince_decrypt_kat<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::prince_decrypt);
    prince_decrypt_kat_test(param, executor);
}

// Random inputs compared against a plaintext PRINCEv2 model, plus the
// decrypt(encrypt(m)) == m round trip.
fn integer_prince_encrypt_decrypt_random<P>(param: P)
where
    P: Into<TestParameters>,
{
    let encrypt_executor = GpuFunctionExecutor::new(&CudaServerKey::prince_encrypt);
    let decrypt_executor = GpuFunctionExecutor::new(&CudaServerKey::prince_decrypt);
    prince_encrypt_decrypt_random_test(param, encrypt_executor, decrypt_executor);
}

// The same KATs with key material prepared once and used for two runs
fn prince_encrypt_with_reused_keys(
    sks: &CudaServerKey,
    input: &CudaUnsignedRadixCiphertext,
    k0: &CudaUnsignedRadixCiphertext,
    k1: &CudaUnsignedRadixCiphertext,
    num_prince_inputs: usize,
    streams: &CudaStreams,
) -> CudaUnsignedRadixCiphertext {
    let keys = sks.prince_encrypt_init(k0, k1, streams);
    let _ = sks.prince_next(&keys, input, num_prince_inputs, streams);
    sks.prince_next(&keys, input, num_prince_inputs, streams)
}

fn prince_decrypt_with_reused_keys(
    sks: &CudaServerKey,
    input: &CudaUnsignedRadixCiphertext,
    k0: &CudaUnsignedRadixCiphertext,
    k1: &CudaUnsignedRadixCiphertext,
    num_prince_inputs: usize,
    streams: &CudaStreams,
) -> CudaUnsignedRadixCiphertext {
    let keys = sks.prince_decrypt_init(k0, k1, streams);
    let _ = sks.prince_next(&keys, input, num_prince_inputs, streams);
    sks.prince_next(&keys, input, num_prince_inputs, streams)
}

fn integer_prince_encrypt_kat_reused_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&prince_encrypt_with_reused_keys);
    prince_encrypt_kat_test(param, executor);
}

fn integer_prince_decrypt_kat_reused_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&prince_decrypt_with_reused_keys);
    prince_decrypt_kat_test(param, executor);
}

struct PrinceGuardFixture {
    cks: RadixClientKey,
    sks: CudaServerKey,
    streams: CudaStreams,
    d_message: CudaUnsignedRadixCiphertext,
    d_k0: CudaUnsignedRadixCiphertext,
    d_k1: CudaUnsignedRadixCiphertext,
}

// Valid operands from which each panicking test below violates exactly one
// PRINCE argument check
fn prince_guard_fixture() -> PrinceGuardFixture {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(cks.as_ref(), &streams);
    let to_gpu = |v: u64| {
        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cks.encrypt_u64_for_prince(v), &streams)
    };
    let d_message = to_gpu(0x0123456789abcdef);
    let d_k0 = to_gpu(0x0123456789abcdef);
    let d_k1 = to_gpu(0xfedcba9876543210);
    PrinceGuardFixture {
        cks,
        sks,
        streams,
        d_message,
        d_k0,
        d_k1,
    }
}

#[test]
#[should_panic(expected = "PRINCE requires 2_2 parameters")]
fn test_gpu_integer_prince_rejects_non_2_2_parameters() {
    let param = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128;
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, 1));
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(cks.as_ref(), &streams);
    let d_k = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.encrypt_u64_for_prince(0),
        &streams,
    );
    let _ = sks.prince_encrypt_init(&d_k, &d_k, &streams);
}

#[test]
#[should_panic(expected = "PRINCE k0 must contain 32 blocks")]
fn test_gpu_integer_prince_rejects_short_k0() {
    let f = prince_guard_fixture();
    let short = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &f.cks.encrypt_u64s_for_prince(&[0, 0]),
        &f.streams,
    );
    let _ = f.sks.prince_encrypt_init(&short, &f.d_k1, &f.streams);
}

#[test]
#[should_panic(expected = "PRINCE k1 must contain 32 blocks")]
fn test_gpu_integer_prince_rejects_short_k1() {
    let f = prince_guard_fixture();
    let short = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &f.cks.encrypt_u64s_for_prince(&[0, 0]),
        &f.streams,
    );
    let _ = f.sks.prince_encrypt_init(&f.d_k0, &short, &f.streams);
}

#[test]
#[should_panic(expected = "PRINCE input must contain 64 blocks for 2 inputs")]
fn test_gpu_integer_prince_rejects_input_batch_mismatch() {
    let f = prince_guard_fixture();
    let keys = f.sks.prince_encrypt_init(&f.d_k0, &f.d_k1, &f.streams);
    let _ = f.sks.prince_next(&keys, &f.d_message, 2, &f.streams);
}

#[test]
#[should_panic(expected = "PRINCE k0 blocks must be fresh encryptions")]
fn test_gpu_integer_prince_rejects_non_fresh_key() {
    let f = prince_guard_fixture();
    let stale = f.sks.unchecked_add(&f.d_k0, &f.d_k0, &f.streams);
    let _ = f.sks.prince_encrypt_init(&stale, &f.d_k1, &f.streams);
}

#[test]
#[should_panic(expected = "PRINCE input blocks must be fresh encryptions")]
fn test_gpu_integer_prince_rejects_non_fresh_input() {
    let f = prince_guard_fixture();
    let keys = f.sks.prince_encrypt_init(&f.d_k0, &f.d_k1, &f.streams);
    let stale = f.sks.unchecked_add(&f.d_message, &f.d_message, &f.streams);
    let _ = f.sks.prince_next(&keys, &stale, 1, &f.streams);
}
