//! Production decomposition parameters. See the comment above [`tier1`](super::tier1)'s
//! parameters for the `sigma_FP` vs. gadget-step derivation that puts these parameters on the
//! statistical side of the tier split.
//!
//! The two implementations' output noise is nearly uncorrelated rather than nearly identical.
//! Once the CPU and GPU accumulators separate by more than one gadget step, the two sides round to
//! different decomposition digits and their decomposition residuals become independent draws. At
//! these parameters the floating-point separation reaches about 2^63 while the finest gadget step,
//! `q / B^l` for section two's mask, is 2^56, so the separation exceeds the step and decorrelation
//! is essentially complete. The observed distribution of the ratio of the two noise sums (see the
//! flake-rate measurements in the test's commit) matches the zero-correlation prediction, so this
//! is measured rather than assumed. That is why this tier compares decrypted phases with a
//! tolerance instead of comparing ciphertext coefficients: one flipped digit changes the output
//! ciphertext mask by a uniform torus element while changing the phase by only one gadget step, so
//! a coefficient comparison would fail on a correct implementation. The gentler tier exists for the
//! opposite reason: there the separation is about 2^38.7 and the finest gadget step is 2^104, 66
//! bits above it, so no digit ever flips and the coefficients can be compared directly.
//!
//! The 2^63.1 and 2^56.1 figures above come from `sigma_FP = q * 2^-106 * (B/2) * R *
//! sqrt(n * N / 18)` per section (see [`tier1`](super::tier1)'s comment for the full form), with
//! `R = k * l_mask + l_body` the rows accumulated per output polynomial and `n` the section's
//! external product count: section one has `R = 6`, `n = 286`; section two has `R = 8`, `n = 632`.
//!
//! The statistic bounds the *variance* of the noise the GPU bootstrap adds relative to the CPU
//! one, over all 16 messages of the production message space (message_modulus 4 * carry_modulus 4,
//! matching `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`), independent of batch size. For each
//! message `m`, let `e_cpu` and `e_gpu` be the signed torus distance from the decrypted plaintext
//! to the exact encoded value `m * delta`, and `d = e_gpu - e_cpu`; `S_cpu`, `S_gpu` and `S_d` are
//! the sums of their squares over the 16 messages. For identically distributed `X` and `Y` at any
//! correlation, `Var(X - Y) <= (sd(X) + sd(Y))^2 = 4 Var(X)` (from `Var(X-Y) = Var(X) + Var(Y) -
//! 2 Cov(X,Y) <= Var(X) + Var(Y) + 2 sd(X) sd(Y)`, using `sd(X) = sd(Y)`), so `Var(d) / Var(e_cpu)`
//! cannot exceed 4 in population, whatever the parameters: 4 is a hard, parameter-free floor for
//! any valid ceiling. The test below asserts `S_d <= 9.0 * S_cpu`. The Gaussian approximation
//! behind this (the noise is a sum over hundreds of external products and thousands of
//! coefficients, so the central limit theorem applies, but this is an approximation, not an exact
//! distribution) reduces the statistic to an equivalent F(16, 16) comparison; 9 is that
//! comparison's one-sided 1e-4 quantile at zero correlation, the worst case (real, positive
//! correlation only pushes the true quantile down, so 9 stays safe as correlation departs from
//! zero). That is the rule to recompute if the sample count ever changes.
//!
//! A third check used to bound `S_gpu` and `S_cpu` against each other individually, on the theory
//! that a structurally offset but individually quiet GPU output would escape the difference bound.
//! It was removed: it is strictly dominated by the difference check above, not merely redundant
//! with it. In the zero-correlation regime that holds here, with the GPU adding independent excess
//! variance `v` on top of the shared floor `sigma^2`, `S_gpu / S_cpu = 1 + v / sigma^2` and
//! `S_d / S_cpu = 2 + v / sigma^2` are the same statistic offset by exactly 2, for every value of
//! `v`; at any shared ceiling the difference check always fires first, so there is no defect the
//! magnitude check could catch that the difference check misses. Carrying it doubled the flake
//! budget for zero additional coverage. When the difference check does fail, it prints `S_gpu` and
//! `S_cpu` and their ratio so the failure message still says whether the GPU is noisier, quieter,
//! or merely different from the reference — a GPU quieter than the reference while still decoding
//! correctly is the interesting case, since it suggests the GPU skipped part of the computation.
//!
//! This variance check exists because of exactly one failure mode plain decoding at these
//! parameters cannot see: a dropped decomposition level. Every other layout bug considered (a
//! transposed layout, an off-by-one split point, swapped mask/body base logs, a section using the
//! other's parameters) moves the phase error by up to 2^96 or misaligns every later key read,
//! making decryption uniform on the torus, which the decode assertion below already catches. A
//! dropped level instead raises the noise from about 2^72 to about 2^88, which still decodes
//! correctly (35 bits under the message threshold) and is invisible to decoding alone; only the
//! variance bound sees it, growing `S_gpu` relative to `S_cpu` by roughly `2^32`, orders of
//! magnitude past the ceiling above. The sample count matters for this check too, not only for the
//! magnitude check that was removed: at 8 samples instead of 16, a ceiling of 9 flakes around one
//! run in fifty rather than the intended one in ten thousand, so both the statistic and its
//! reliability depend on using all 16 messages regardless of batch size.
//!
//! 16 messages, not fewer, also guards against the mild form of a split-point error: mask element
//! `a_i` paired with GGSW row `i+1` (rather than every row shifting, which decoding already
//! catches) lands on a uniformly wrong lookup table box and escapes detection with probability
//! 1/16 per message. Sixteen messages is chosen to catch that specifically, not picked round.
//!
//! No golden data: the batch-size dependent kernel selection makes the existing golden recipe's
//! batch-independence assumption false for this key (see [`CG_VARIANT_MAX_BATCH_SIZE`]), and the
//! determinism / batch-size-independence checks already exercised here cover the same blind spot
//! without committed data whose format would need to track a reference implementation that can
//! still change.

use super::super::is_sanitizer_run;
use super::{
    assert_batch_size_independent, assert_determinism_at_batch_size, batched_input,
    run_halfhalf_batch, CG_VARIANT_MAX_BATCH_SIZE,
};
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seed};
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaHalfhalfBootstrapKey;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::*;
use crate::shortint::parameters::{
    NoiseSquashingParameters, NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use rand::Rng;

/// One sample per message of the production message space: message_modulus 4 * carry_modulus 4.
/// See the module doc for why this exact count.
const MESSAGE_SPACE: u64 = 16;

const INPUT_LWE_DIMENSION_START: LweDimension = LweDimension(286);
const MASK_BASE_LOG_START: DecompositionBaseLog = DecompositionBaseLog(32);
const MASK_LEVEL_START: DecompositionLevelCount = DecompositionLevelCount(2);
const BODY_BASE_LOG_START: DecompositionBaseLog = DecompositionBaseLog(31);
const BODY_LEVEL_START: DecompositionLevelCount = DecompositionLevelCount(2);
const MASK_BASE_LOG_END: DecompositionBaseLog = DecompositionBaseLog(24);
const MASK_LEVEL_END: DecompositionLevelCount = DecompositionLevelCount(3);
const BODY_BASE_LOG_END: DecompositionBaseLog = DecompositionBaseLog(31);
const BODY_LEVEL_END: DecompositionLevelCount = DecompositionLevelCount(2);

/// See the module doc for the derivation: 4 is the hard, parameter-free population floor on
/// `Var(d) / Var(e_cpu)`; 9 is the one-sided 1e-4 quantile of the equivalent F(16, 16) comparison
/// at zero correlation (the worst case), which is what must be recomputed if the sample count
/// changes.
const MAX_DIFF_TO_CPU_VARIANCE_RATIO: f64 = 9.0;

struct Tier2Fixture {
    streams: CudaStreams,
    gpu_bsk: CudaHalfhalfBootstrapKey,
    cpu_fourier_bsk: Fourier128HalfProductHalfRotateLweBootstrapKeyOwned,
    accumulator_cpu: GlweCiphertextOwned<u128>,
    d_accumulator: crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList<u128>,
    small_lwe_sk: LweSecretKeyOwned<u64>,
    big_lwe_sk: LweSecretKeyOwned<u128>,
    output_lwe_dimension: LweDimension,
    delta_u64: u64,
    delta_u128: u128,
}

/// Asserts on the parameters themselves that the test is exercising the halfhalf key format's
/// full generality, so a later edit cannot quietly flatten it back into an ordinary bootstrap
/// that would still pass.
fn assert_parameters_are_genuinely_exercised() {
    const {
        assert!(
            BODY_LEVEL_END.0 < MASK_LEVEL_END.0,
            "section two's body level count must stay strictly below its mask level count: that \
            is the only configuration that reaches the kernel's zero-fill branch for unused body \
            levels"
        );
    }
    const {
        assert!(
            BODY_BASE_LOG_START.0 != MASK_BASE_LOG_START.0,
            "section one's body base log must differ from its mask base log: with equal level \
            counts and no stride change, equal base logs would degenerate to ordinary \
            half-product, which section two's differing level counts already cover"
        );
    }
    const {
        assert!(
            MASK_BASE_LOG_START.0 != MASK_BASE_LOG_END.0 || MASK_LEVEL_START.0 != MASK_LEVEL_END.0,
            "the two sections' mask parameters must differ from each other: equal mask \
            parameters would make this half-product with a mask split rather than genuine \
            half-rotate"
        );
    }
    const {
        assert!(
            INPUT_LWE_DIMENSION_START.0
                != PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    .lwe_dimension
                    .0
                    - INPUT_LWE_DIMENSION_START.0,
            "the split must be asymmetric, so an off-by-one or a swapped-section error cannot \
            cancel"
        );
    }
}

impl Tier2Fixture {
    fn new() -> Self {
        assert_parameters_are_genuinely_exercised();

        let NoiseSquashingParameters::Classic(squash_params) =
            NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        else {
            panic!("multi-bit noise squashing PBS is not supported on GPU");
        };
        let input_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let lwe_dimension = input_params.lwe_dimension;
        let glwe_dimension = squash_params.glwe_dimension;
        let polynomial_size = squash_params.polynomial_size;
        let glwe_size = glwe_dimension.to_glwe_size();
        let ciphertext_modulus = squash_params.ciphertext_modulus;
        let glwe_noise_distribution = squash_params.glwe_noise_distribution;

        // Deterministic and printed on every run (visible in the captured output of a failing
        // test), so a red run can be reproduced exactly by hardcoding this value.
        let seed: u128 = rand::thread_rng().gen();
        println!("halfhalf PBS128 tier2: seed = {seed:#034x}");
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );
        let mut secret_random_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(deterministic_seeder.seed());

        let small_lwe_sk: LweSecretKeyOwned<u64> =
            LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);
        let glwe_sk: GlweSecretKeyOwned<u128> = GlweSecretKey::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_random_generator,
        );
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
        let output_lwe_dimension = big_lwe_sk.lwe_dimension();

        let std_bsk = par_allocate_and_generate_new_half_product_half_rotate_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            INPUT_LWE_DIMENSION_START,
            MASK_BASE_LOG_START,
            MASK_LEVEL_START,
            BODY_BASE_LOG_START,
            BODY_LEVEL_START,
            MASK_BASE_LOG_END,
            MASK_LEVEL_END,
            BODY_BASE_LOG_END,
            BODY_LEVEL_END,
            glwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_random_generator,
        );

        let cpu_fourier_bsk =
            par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128(
                &std_bsk,
            );

        let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
        // `None`: the plain modulus switch, matching the CPU reference bootstrap.
        let gpu_bsk = CudaHalfhalfBootstrapKey::from_lwe_half_product_half_rotate_bootstrap_key(
            &std_bsk, None, &streams,
        );

        let delta_u64: u64 = (1u64 << 63) / MESSAGE_SPACE;
        let delta_u128: u128 = (1u128 << 127) / MESSAGE_SPACE as u128;
        let accumulator_cpu: GlweCiphertextOwned<u128> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_size,
            MESSAGE_SPACE as usize,
            ciphertext_modulus,
            delta_u128,
            |x| x,
        );
        let d_accumulator =
            crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList::from_glwe_ciphertext(
                &accumulator_cpu,
                &streams,
            );

        Self {
            streams,
            gpu_bsk,
            cpu_fourier_bsk,
            accumulator_cpu,
            d_accumulator,
            small_lwe_sk,
            big_lwe_sk,
            output_lwe_dimension,
            delta_u64,
            delta_u128,
        }
    }

    fn encrypt(
        &self,
        message: u64,
        generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    ) -> LweCiphertextOwned<u64> {
        let input_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        allocate_and_encrypt_new_lwe_ciphertext(
            &self.small_lwe_sk,
            Plaintext(message * self.delta_u64),
            input_params.lwe_noise_distribution,
            CiphertextModulus::<u64>::new_native(),
            generator,
        )
    }

    fn cpu_reference(&self, lwe_in: &LweCiphertextOwned<u64>) -> LweCiphertextOwned<u128> {
        let mut cpu_out = LweCiphertext::new(
            0u128,
            self.output_lwe_dimension.to_lwe_size(),
            self.accumulator_cpu.ciphertext_modulus(),
        );
        half_product_half_rotate_programmable_bootstrap_f128_lwe_ciphertext(
            lwe_in,
            &mut cpu_out,
            &self.accumulator_cpu,
            &self.cpu_fourier_bsk,
        );
        cpu_out
    }
}

/// The signed torus distance of `decrypted` from the exact encoded plaintext `exact`, i.e. the
/// decryption error, interpreted as a value in `(-2^127, 2^127]` rather than `[0, 2^128)`.
fn signed_torus_distance(decrypted: u128, exact: u128) -> i128 {
    decrypted.wrapping_sub(exact) as i128
}

/// Asserts a message round-trips through decryption and rounding to the lookup table value it was
/// encoded with, at the production message space.
fn assert_decodes_correctly(decrypted: u128, message: u64, delta_u128: u128, context: &str) {
    // The 5 MSBs (4 bits of message plus one bit of padding) are kept, matching the message
    // space's own encoding.
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
    let decoded = signed_decomposer.closest_representable(decrypted) / delta_u128;
    assert_eq!(
        decoded, message as u128,
        "{context}: decoded {decoded}, expected {message}"
    );
}

/// Bootstraps every message in the production message space (`MESSAGE_SPACE` samples, always,
/// whatever `batch_size` is) and checks the GPU noise statistics against the CPU reference, per
/// the bound derived in the module doc. `batch_size` only selects how the `MESSAGE_SPACE` samples
/// are split across GPU launches, and therefore which kernel variant runs: it must evenly divide
/// `MESSAGE_SPACE` so every launch carries the same number of lanes.
fn assert_statistics_at_batch_size(fixture: &Tier2Fixture, batch_size: usize) {
    assert!(
        batch_size <= MESSAGE_SPACE as usize && (MESSAGE_SPACE as usize).is_multiple_of(batch_size),
        "batch_size must evenly divide the message space so every launch carries a full batch"
    );

    let seed: u128 = rand::thread_rng().gen();
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    let mut encryption_random_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        deterministic_seeder.seed(),
        &mut deterministic_seeder,
    );

    let messages: Vec<u64> = (0..MESSAGE_SPACE).collect();
    let inputs: Vec<LweCiphertextOwned<u64>> = messages
        .iter()
        .map(|&m| fixture.encrypt(m, &mut encryption_random_generator))
        .collect();

    // `batch_size` selects the kernel variant; every chunk of that size is a separate GPU launch,
    // and all `MESSAGE_SPACE` samples across every launch feed the same statistic.
    let mut gpu_plaintexts: Vec<Plaintext<u128>> = Vec::with_capacity(MESSAGE_SPACE as usize);
    for chunk in inputs.chunks(batch_size) {
        let d_input = batched_input(chunk, &fixture.streams);
        let gpu_out = run_halfhalf_batch(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &d_input,
            fixture.output_lwe_dimension,
            &fixture.streams,
        );
        for lane in 0..chunk.len() {
            let gpu_lane = LweCiphertext::from_container(
                gpu_out.get(lane).into_container().to_vec(),
                gpu_out.ciphertext_modulus(),
            );
            gpu_plaintexts.push(decrypt_lwe_ciphertext(&fixture.big_lwe_sk, &gpu_lane));
        }

        if !is_sanitizer_run() {
            assert_determinism_at_batch_size(
                &fixture.gpu_bsk,
                &fixture.d_accumulator,
                &d_input,
                fixture.output_lwe_dimension,
                &fixture.streams,
                &gpu_out,
                &format!("halfhalf PBS128 tier2 production params, batch size {batch_size}"),
            );
        }
    }

    // Sums of squares in f64: the error magnitudes sit near 2^72, so their squares reach 2^144
    // and would silently overflow an integer accumulator.
    let mut sum_d_squared = 0f64;
    let mut sum_e_cpu_squared = 0f64;
    let mut sum_e_gpu_squared = 0f64;
    let mut per_sample = Vec::with_capacity(MESSAGE_SPACE as usize);

    for (&message, (lwe_in, &gpu_plaintext)) in messages
        .iter()
        .zip(inputs.iter().zip(gpu_plaintexts.iter()))
    {
        let exact = message as u128 * fixture.delta_u128;

        let cpu_out = fixture.cpu_reference(lwe_in);
        let cpu_plaintext: Plaintext<u128> = decrypt_lwe_ciphertext(&fixture.big_lwe_sk, &cpu_out);

        assert_decodes_correctly(
            cpu_plaintext.0,
            message,
            fixture.delta_u128,
            &format!("tier2 batch size {batch_size}, message {message}: CPU"),
        );
        assert_decodes_correctly(
            gpu_plaintext.0,
            message,
            fixture.delta_u128,
            &format!("tier2 batch size {batch_size}, message {message}: GPU"),
        );

        let e_cpu = signed_torus_distance(cpu_plaintext.0, exact) as f64;
        let e_gpu = signed_torus_distance(gpu_plaintext.0, exact) as f64;
        let d = e_gpu - e_cpu;

        sum_d_squared += d * d;
        sum_e_cpu_squared += e_cpu * e_cpu;
        sum_e_gpu_squared += e_gpu * e_gpu;
        per_sample.push((message, e_cpu, e_gpu, d));
    }

    // Printed unconditionally: cargo test only shows captured stdout for a failing test, so this
    // costs nothing when the assertions below pass and gives a full diagnosis when they don't.
    println!(
        "halfhalf PBS128 tier2 batch size {batch_size}: seed = {seed:#034x}, \
        log2(S_cpu) = {:.2}, log2(S_gpu) = {:.2}, log2(S_d) = {:.2}, \
        S_gpu/S_cpu = {:.3}, S_cpu/S_gpu = {:.3}, S_d/S_cpu = {:.3}",
        sum_e_cpu_squared.log2(),
        sum_e_gpu_squared.log2(),
        sum_d_squared.log2(),
        sum_e_gpu_squared / sum_e_cpu_squared,
        sum_e_cpu_squared / sum_e_gpu_squared,
        sum_d_squared / sum_e_cpu_squared,
    );
    for (message, e_cpu, e_gpu, d) in &per_sample {
        println!(
            "  message {message}: e_cpu = {e_cpu:+.0} (2^{:.1}), e_gpu = {e_gpu:+.0} (2^{:.1}), \
            d = {d:+.0}",
            e_cpu.abs().log2(),
            e_gpu.abs().log2(),
        );
    }

    assert!(
        sum_d_squared <= MAX_DIFF_TO_CPU_VARIANCE_RATIO * sum_e_cpu_squared,
        "tier2 batch size {batch_size}: sum(d^2) = {sum_d_squared} exceeds {} * sum(e_cpu^2) = {} \
        (sum(e_cpu^2) = {sum_e_cpu_squared}, sum(e_gpu^2) = {sum_e_gpu_squared}, \
        S_gpu/S_cpu = {:.3} tells whether the GPU is noisier, quieter, or merely different from \
        the reference)",
        MAX_DIFF_TO_CPU_VARIANCE_RATIO,
        MAX_DIFF_TO_CPU_VARIANCE_RATIO * sum_e_cpu_squared,
        sum_e_gpu_squared / sum_e_cpu_squared,
    );
}

#[test]
fn test_halfhalf_pbs128_tier2_production_params_matches_cpu_reference() {
    let fixture = Tier2Fixture::new();

    assert_statistics_at_batch_size(&fixture, 8);
    assert_statistics_at_batch_size(&fixture, 16);

    if !is_sanitizer_run() {
        let seed: u128 = rand::thread_rng().gen();
        let mut deterministic_seeder =
            DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );
        let lwe_in = fixture.encrypt(1, &mut encryption_random_generator);
        assert_batch_size_independent(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &lwe_in,
            fixture.output_lwe_dimension,
            &fixture.streams,
            // `[1, 2]`: see the note on `CG_VARIANT_MAX_BATCH_SIZE`'s definition. Batch 8 needs 72
            // resident blocks for the cooperative-groups occupancy probe to succeed, batch 2 only
            // 18, so this pair stays portable to devices smaller than this 4090.
            &[1, 2],
            "halfhalf PBS128 tier2 production params, cooperative-groups variant",
        );
        assert_batch_size_independent(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &lwe_in,
            fixture.output_lwe_dimension,
            &fixture.streams,
            &[CG_VARIANT_MAX_BATCH_SIZE + 1, 16],
            "halfhalf PBS128 tier2 production params, default variant",
        );
    }
}
