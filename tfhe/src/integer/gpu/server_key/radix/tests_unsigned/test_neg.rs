use super::legacy_default_tests::{legacy_default_neg_test, legacy_default_overflowing_neg_test};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_neg::unchecked_neg_test;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_neg);
create_gpu_parameterized_test!(integer_neg);
create_gpu_parameterized_test!(integer_overflowing_neg);

fn integer_unchecked_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_neg);
    unchecked_neg_test(param, executor);
}

fn integer_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::neg);
    legacy_default_neg_test(param, executor);
}

fn integer_overflowing_neg(param: impl Into<TestParameters>) {
    let executor = GpuFunctionExecutor::new(&CudaServerKey::overflowing_neg);
    legacy_default_overflowing_neg_test(param, executor);
}

/// GPU negation of blocks whose degree exceeds the message modulus (the CPU's correcting term z
/// grows to ceil(degree / B) * B there) gives the CPU's value and degrees.
#[test]
fn test_gpu_integer_unchecked_neg_high_degree() {
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::gen_keys_gpu;
    use crate::integer::{RadixCiphertext, ServerKey};

    const NUM_BLOCKS: usize = 4;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    let cpu_sks = ServerKey::new_radix_server_key(&cks);
    let modulus = 1u64 << (2 * NUM_BLOCKS);
    // Value of the radix including the carries
    let value = |c: &RadixCiphertext| {
        c.blocks.iter().rev().fold(0u64, |acc, b| {
            (acc * 4 + cks.key.decrypt_message_and_carry(b)) % modulus
        })
    };
    for values in [
        vec![255u64, 255],
        vec![200, 77, 13],
        vec![255, 255, 255],
        vec![0, 0, 0],
    ] {
        // Unchecked sums: block degrees 6 and 9
        let cts: Vec<RadixCiphertext> = values
            .iter()
            .map(|&v| cks.encrypt_radix(v, NUM_BLOCKS))
            .collect();
        let mut input = cts[0].clone();
        for ct in &cts[1..] {
            cpu_sks.unchecked_add_assign(&mut input, ct);
        }
        assert!(input.blocks.iter().all(|b| b.degree.get() >= 6));
        let expected = (modulus - values.iter().sum::<u64>() % modulus) % modulus;

        let cpu = cpu_sks.unchecked_neg(&input);
        let d_input = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&input, &streams);
        let gpu = sks
            .unchecked_neg(&d_input, &streams)
            .to_radix_ciphertext(&streams);
        assert_eq!(value(&cpu), expected, "CPU {values:?}");
        assert_eq!(value(&gpu), expected, "GPU {values:?}");
        let degrees = |c: &RadixCiphertext| c.blocks.iter().map(|b| b.degree).collect::<Vec<_>>();
        assert_eq!(degrees(&gpu), degrees(&cpu), "degrees {values:?}");
    }
}
