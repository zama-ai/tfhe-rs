use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seed};
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::{ClientKey, CompressedServerKey, RadixClientKey};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{
    ShortintParameterSet, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use rand::Rng;
use std::fmt::Write;
use tfhe_cuda_backend::bindings::cuda_fft16x4x16_is_supported_async;

// ============================================================================
// Bit-wise regression ("golden values") data for the GPU `sum_ciphertexts`.
//
// Integer counterpart of the core_crypto GPU golden tests (`pbs_golden`,
// `pbs128_golden`): a fixed seed and fixed clear inputs drive a fully
// deterministic pipeline, and the raw output limbs are committed so any change
// in the GPU result shows up bit for bit.
//
// Everything the pipeline needs is committed in the generated data file:
//
//   sum_ciphertexts_golden_data/sum_ciphertexts_golden_v1.rs
//     GOLDEN_SEED                 seeds the ShortintEngine (keys + encryptions)
//     INPUT_MESSAGES              NUM_INPUTS clears, encrypted in this order
//     CLASSICAL_EXPECTED          output block limbs, classic 2_2
//     MULTI_BIT_GROUP_4_EXPECTED  output block limbs, multi-bit 2_2 gf 4
//
// Per parameter set, the pipeline is:
//
//   Seed(GOLDEN_SEED) ──> seeded thread-local ShortintEngine
//     ├─> ClientKey::new                         (secret keys)
//     ├─> CompressedServerKey (radix)            (BSK + KSK, seeded)
//     │     └─> CudaServerKey::decompress_from_cpu
//     └─> encrypt INPUT_MESSAGES[0..NUM_INPUTS]  (masks + noise, in order)
//           └─> sum_ciphertexts on GPU 0 ──> output limbs
//
// `CudaServerKey::new` is deliberately *not* used: it builds its own
// `ShortintEngine::new()` from the OS entropy, so its keys would differ on every
// run whatever the thread-local engine is seeded with.
//
// The GPU FFT is only bit-reproducible within a GPU generation and the PBS
// golden data is captured on H100, so the data must be generated on compute
// capability 9.x (H100) or newer.
// ============================================================================

/// Number of radix blocks of every input and of the output.
const NUM_BLOCKS: usize = 4;

/// Number of ciphertexts in the vector given to `sum_ciphertexts`.
const NUM_INPUTS: usize = 16;

/// The golden data is captured on an H100 and the GPU FFT is only guaranteed
/// bit-reproducible within a GPU generation, so it is only generated (and
/// checked) on Hopper (compute capability 9.x) and newer.
///
/// NOTE: this reuses the FFT16x4x16 capability probe, which is implemented in
/// the CUDA backend as a pure `prop.major >= 9` (Hopper / H100+) device query.
fn hopper_or_newer_is_supported() -> bool {
    // Safe: a pure runtime device-capability query with no aliasing concerns.
    unsafe { cuda_fft16x4x16_is_supported_async(0) }
}

/// Replaces this thread's `ShortintEngine` by one seeded from `seed`, so every
/// key generation and encryption that follows on this thread is reproducible.
/// The engine is reinstalled before each parameter set, so the order in which
/// the parameter sets run does not change their data.
fn install_seeded_shortint_engine(seed: u128) {
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    let seeded_engine = ShortintEngine::new_from_seeder(&mut deterministic_seeder);
    ShortintEngine::with_thread_local_mut(|local_engine| *local_engine = seeded_engine);
}

/// Deterministically generates the keys for `params` from `seed`, encrypts
/// `messages` in order, sums them on GPU 0 with `sum_ciphertexts`, and returns
/// the raw limbs (mask followed by body) of every output block.
///
/// The sum is run twice on the same inputs: both runs must agree bit for bit,
/// and the result must decrypt to the clear sum, so a non-deterministic or
/// incorrect output is never frozen as golden data.
fn run_sum_ciphertexts_golden<P>(params: P, seed: u128, messages: &[u64]) -> Vec<Vec<u64>>
where
    P: TryInto<ShortintParameterSet>,
    <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
{
    // The draw order from the seeded engine (client key, then server key, then
    // the encryptions) fixes every random value, so it must never change.
    install_seeded_shortint_engine(seed);
    let cks = ClientKey::new(params);
    let compressed_sks = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let cks = RadixClientKey::from((cks, NUM_BLOCKS));

    // Single GPU: a multi-GPU stream set would split the work across devices.
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let sks = CudaServerKey::decompress_from_cpu(&compressed_sks, &streams);

    let modulus = cks.parameters().message_modulus().0.pow(NUM_BLOCKS as u32);
    assert!(
        messages.iter().all(|&m| m < modulus),
        "every input message must be below message_modulus^NUM_BLOCKS = {modulus}"
    );

    let cts: Vec<_> = messages.iter().map(|&m| cks.encrypt(m)).collect();

    // `sum_ciphertexts` consumes its inputs, so each run gets its own upload.
    let run_sum = || {
        let d_cts: Vec<_> = cts
            .iter()
            .map(|ct| CudaUnsignedRadixCiphertext::from_radix_ciphertext(ct, &streams))
            .collect();
        sks.sum_ciphertexts(d_cts, &streams)
            .expect("sum_ciphertexts returned no result for a non-empty input")
            .to_radix_ciphertext(&streams)
    };
    let result = run_sum();
    let result_again = run_sum();

    let limbs: Vec<Vec<u64>> = result
        .blocks
        .iter()
        .map(|block| block.ct.as_ref().to_vec())
        .collect();
    let limbs_again: Vec<Vec<u64>> = result_again
        .blocks
        .iter()
        .map(|block| block.ct.as_ref().to_vec())
        .collect();
    assert_eq!(
        limbs, limbs_again,
        "two GPU sum_ciphertexts runs on the same input gave different outputs"
    );

    assert!(result.block_carries_are_empty());
    let decrypted: u64 = cks.decrypt(&result);
    let expected = messages.iter().sum::<u64>() % modulus;
    assert_eq!(
        decrypted, expected,
        "GPU sum_ciphertexts produced an incorrect result"
    );

    limbs
}

/// Formats a `pub const <name>: &[&[u64]] = &[...]` block holding one inner
/// slice of hex limbs per output block, in block order.
fn format_golden_const(name: &str, blocks: &[Vec<u64>]) -> String {
    let mut body = String::new();
    for (index, limbs) in blocks.iter().enumerate() {
        let _ = writeln!(body, "    // block {index}");
        let _ = writeln!(body, "    &[");
        for limb in limbs {
            let _ = writeln!(body, "        {limb:#018x},");
        }
        let _ = writeln!(body, "    ],");
    }
    format!("pub const {name}: &[&[u64]] = &[\n{body}];\n\n")
}

/// (Re)generates the `sum_ciphertexts` golden file from a fresh random seed and
/// fresh random clear inputs.
///
/// This is *not* a regression test: it is `#[ignore]`d so no test run ever
/// executes it, and is run by hand on an H100 (sm_90) with
/// `cargo test ... generate_sum_ciphertexts_golden -- --ignored --exact`,
/// then the regenerated file is committed.
#[test]
#[ignore = "maintenance helper: regenerates the golden data, run by hand on an H100"]
fn generate_sum_ciphertexts_golden() {
    if !hopper_or_newer_is_supported() {
        println!(
            "skipping generate_sum_ciphertexts_golden: the golden data requires compute \
             capability 9.x (H100) or newer"
        );
        return;
    }

    // Both parameter sets share the inputs, so they must share the plaintext space.
    let classical = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let multi_bit = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    assert_eq!(classical.message_modulus, multi_bit.message_modulus);
    let modulus = classical.message_modulus.0.pow(NUM_BLOCKS as u32);

    let mut rng = rand::thread_rng();
    let seed: u128 = rng.gen();
    let messages: Vec<u64> = (0..NUM_INPUTS).map(|_| rng.gen_range(0..modulus)).collect();
    println!("seed: {seed:#034x}, messages: {messages:?}");

    let classical_limbs = run_sum_ciphertexts_golden(classical, seed, &messages);
    let multi_bit_limbs = run_sum_ciphertexts_golden(multi_bit, seed, &messages);

    let mut contents = String::from(
        "// @generated by the `generate_sum_ciphertexts_golden` helper in\n\
         // integer::gpu::server_key::radix::tests_unsigned::sum_ciphertexts_golden.\n\
         // Do not edit by hand.\n",
    );
    let _ = writeln!(contents, "pub const GOLDEN_SEED: u128 = {seed:#034x};\n");
    // Short integer elements are packed on one line, which is how rustfmt lays
    // them out, so the generated file stays unchanged under formatting.
    let message_list = messages
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        contents,
        "pub const INPUT_MESSAGES: &[u64] = &[\n    {message_list},\n];\n"
    );
    contents += &format_golden_const("CLASSICAL_EXPECTED", &classical_limbs);
    contents += &format_golden_const("MULTI_BIT_GROUP_4_EXPECTED", &multi_bit_limbs);

    // Normalize to a single trailing newline so the generated file needs no
    // manual formatting pass after regeneration.
    let contents = format!("{}\n", contents.trim_end());

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/integer/gpu/server_key/radix/tests_unsigned/sum_ciphertexts_golden/\
         sum_ciphertexts_golden_data"
    );
    std::fs::create_dir_all(dir).expect("failed to create the golden data directory");
    let path = format!("{dir}/sum_ciphertexts_golden_v1.rs");
    std::fs::write(&path, contents).expect("failed to write the sum_ciphertexts golden file");
    println!("wrote sum_ciphertexts golden data to {path}");
}
