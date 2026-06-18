use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::{gen_keys_radix_gpu, CudaServerKey};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kreyvium::{
    kreyvium_comparison_test, kreyvium_stateful_comparison_test, kreyvium_test_vector_1_test,
};
use crate::integer::{RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(integer_kreyvium_test_vector_1 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_kreyvium_comparison {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_kreyvium_stateful_comparison {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_kreyvium_batched_matches_single {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn integer_kreyvium_test_vector_1<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::kreyvium_generate_keystream);
    kreyvium_test_vector_1_test(param, executor);
}

fn integer_kreyvium_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::kreyvium_generate_keystream);
    kreyvium_comparison_test(param, executor);
}

fn integer_kreyvium_stateful_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        GpuFunctionExecutor::new((CudaServerKey::kreyvium_init, CudaServerKey::kreyvium_next));
    kreyvium_stateful_comparison_test(param, executor);
}

fn integer_kreyvium_batched_matches_single<P>(param: P)
where
    P: Into<TestParameters>,
{
    kreyvium_batched_matches_single_test(param, &CudaServerKey::kreyvium_generate_keystream);
}

pub(crate) fn kreyvium_batched_matches_single_test<P, F>(param: P, generate_keystream: &F)
where
    P: Into<TestParameters>,
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        usize,
        &CudaStreams,
    ) -> crate::Result<CudaUnsignedRadixCiphertext>,
{
    let param = param.into();
    let streams = CudaStreams::new_multi_gpu();
    let (cks, sks) = gen_keys_radix_gpu(param, 1, &streams);

    let num_steps = 64;
    let lanes: [([u64; 128], [u64; 128]); 2] = [
        (
            std::array::from_fn(|i| (i % 2) as u64),
            std::array::from_fn(|i| (i % 3 == 0) as u64),
        ),
        (
            std::array::from_fn(|i| (i % 3 == 1) as u64),
            std::array::from_fn(|i| (i % 2 == 1) as u64),
        ),
    ];

    let single: Vec<Vec<u64>> = lanes
        .iter()
        .map(|(key_bits, iv_bits)| {
            let d_key = encrypt_bits(&cks, key_bits, &streams);
            let d_iv = encrypt_bits(&cks, iv_bits, &streams);
            let ks = generate_keystream(&sks, &d_key, &d_iv, num_steps, &streams).unwrap();
            decrypt_bits(&cks, &ks.to_radix_ciphertext(&streams))
        })
        .collect();

    // Interleave the two lanes bit-by-bit: block `i * N + j` holds bit `i` of lane `j`.
    let interleave = |selector: fn(&([u64; 128], [u64; 128])) -> &[u64; 128]| {
        (0..128)
            .flat_map(|i| lanes.iter().map(move |lane| selector(lane)[i]))
            .collect::<Vec<_>>()
    };
    let key_interleaved = interleave(|lane| &lane.0);
    let iv_interleaved = interleave(|lane| &lane.1);

    let d_key = encrypt_bits(&cks, &key_interleaved, &streams);
    let d_iv = encrypt_bits(&cks, &iv_interleaved, &streams);
    let batched = generate_keystream(&sks, &d_key, &d_iv, num_steps, &streams).unwrap();
    let batched_bits = decrypt_bits(&cks, &batched.to_radix_ciphertext(&streams));

    let num_inputs = lanes.len();
    assert_eq!(batched_bits.len(), num_steps * num_inputs);
    for (lane, expected) in single.iter().enumerate() {
        let got: Vec<u64> = (0..num_steps)
            .map(|s| batched_bits[s * num_inputs + lane])
            .collect();
        assert_eq!(&got, expected, "lane {lane} keystream mismatch");
    }
}

pub(crate) fn encrypt_bits(
    cks: &RadixClientKey,
    bits: &[u64],
    streams: &CudaStreams,
) -> CudaUnsignedRadixCiphertext {
    let ct = RadixCiphertext::from(
        bits.iter()
            .map(|&bit| cks.encrypt_one_block(bit))
            .collect::<Vec<_>>(),
    );
    CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, streams)
}

pub(crate) fn decrypt_bits(cks: &RadixClientKey, ct: &RadixCiphertext) -> Vec<u64> {
    ct.blocks
        .iter()
        .map(|block| cks.decrypt_one_block(block))
        .collect()
}
