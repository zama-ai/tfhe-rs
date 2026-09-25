//! Gentle decomposition parameters at which the accumulated floating point difference between
//! the CPU and GPU accumulation orders (about 2^38) stays far below the finest gadget step
//! (2^104, the section two body step), so no digit ever flips and a coefficient-wise comparison
//! stays exact. Mirrors the parameters
//! `half_product_half_rotate_matches_classic_bsk_generic` uses in
//! `core_crypto::fft_impl::fft128::crypto::bootstrap_half_product_half_rotate`, except that the
//! two sections get distinct mask/body decomposition parameters here (that test cuts both
//! sections from a single classic key sharing one decomposition, which cannot exercise the
//! per-section mask/body split the halfhalf key format actually supports).
//!
//! Which tier applies to a set of parameters is not a judgment call, so do not move these
//! casually. Per section, the accumulated floating point noise is
//! `sigma_FP = q * 2^-106 * (B/2) * R * sqrt(n * N / 18)`, with `q` the ciphertext modulus, `B`
//! and `l` the section's own base/level pair, `R` the rows accumulated per output polynomial and
//! `n` the section's external product count; that is valid for a coefficient-wise comparison only
//! when `sigma_FP < g / 16`, `g = q / B^l` being the finest gadget step of that base/level pair.
//! At the parameters below, `sigma_FP` is about 2^38.7 against a `g` of 2^104: comfortably inside.
//! At the production parameters in [`super::tier2`], `sigma_FP` is about 2^63.1 against a `g` of
//! 2^56: past the threshold, hence tier2's statistical bound instead of a direct comparison.

use super::super::is_sanitizer_run;
use super::{
    assert_batch_size_independent, assert_determinism_at_batch_size, replicated_input,
    run_halfhalf_batch, CG_VARIANT_MAX_BATCH_SIZE,
};
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seed};
use crate::core_crypto::fft_impl::fft128::crypto::bootstrap_half_product::tests::assert_bootstrap_outputs_close;
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaHalfhalfBootstrapKey;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::CudaStreams;
use crate::core_crypto::prelude::*;
use rand::Rng;

/// Reused across the CPU-only half-product tests: at `u128` the split-limb accumulation sits near
/// the `fft128` mantissa limit, and the deviation between accumulation orders is a function of the
/// random key and input, so the tolerance is set well above what is observed in practice (around
/// 2^40) rather than at a bound a rare draw could exceed.
const MAX_ABS_DIFF: u128 = 1 << 56;

struct Tier1Fixture {
    streams: CudaStreams,
    gpu_bsk: CudaHalfhalfBootstrapKey,
    cpu_fourier_bsk: Fourier128HalfProductHalfRotateLweBootstrapKeyOwned,
    accumulator_cpu: GlweCiphertextOwned<u128>,
    d_accumulator: crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList<u128>,
    lwe_in: LweCiphertextOwned<u64>,
    output_lwe_dimension: LweDimension,
}

impl Tier1Fixture {
    fn new() -> Self {
        let lwe_dimension = LweDimension(30);
        let input_lwe_dimension_start = LweDimension(11);

        let glwe_dimension = GlweDimension(2);
        let polynomial_size = PolynomialSize(512);
        let glwe_size = glwe_dimension.to_glwe_size();
        let ciphertext_modulus = CiphertextModulus::<u128>::new_native();

        let mask_base_log_start = DecompositionBaseLog(11);
        let mask_level_start = DecompositionLevelCount(2);
        let body_base_log_start = DecompositionBaseLog(10);
        let body_level_start = DecompositionLevelCount(2);
        let mask_base_log_end = DecompositionBaseLog(8);
        let mask_level_end = DecompositionLevelCount(3);
        let body_base_log_end = DecompositionBaseLog(10);
        let body_level_end = DecompositionLevelCount(2);

        let glwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000000000000000000000000008645717832544903,
        ));
        let lwe_noise_distribution = DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            0.00000000004998277131225527,
        ));

        // Deterministic and printed on every run (visible in the captured output of a failing
        // test), so a red run can be reproduced exactly by hardcoding this value.
        let seed: u128 = rand::thread_rng().gen();
        println!("halfhalf PBS128 tier1: seed = {seed:#034x}");
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
            input_lwe_dimension_start,
            mask_base_log_start,
            mask_level_start,
            body_base_log_start,
            body_level_start,
            mask_base_log_end,
            mask_level_end,
            body_base_log_end,
            body_level_end,
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

        let message_modulus: u64 = 16;
        let delta: u64 = (1u64 << 63) / message_modulus;
        let delta_u128: u128 = (1u128 << 127) / message_modulus as u128;
        let input_message: u64 = 3;

        let lwe_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            Plaintext(input_message * delta),
            lwe_noise_distribution,
            CiphertextModulus::<u64>::new_native(),
            &mut encryption_random_generator,
        );

        let accumulator_cpu: GlweCiphertextOwned<u128> = generate_programmable_bootstrap_glwe_lut(
            polynomial_size,
            glwe_size,
            message_modulus as usize,
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
            lwe_in,
            output_lwe_dimension,
        }
    }

    /// Runs the CPU reference bootstrap once.
    fn cpu_reference(&self) -> LweCiphertextOwned<u128> {
        let mut cpu_out = LweCiphertext::new(
            0u128,
            self.output_lwe_dimension.to_lwe_size(),
            self.accumulator_cpu.ciphertext_modulus(),
        );
        half_product_half_rotate_programmable_bootstrap_f128_lwe_ciphertext(
            &self.lwe_in,
            &mut cpu_out,
            &self.accumulator_cpu,
            &self.cpu_fourier_bsk,
        );
        cpu_out
    }
}

/// Every lane of a batched GPU bootstrap of the same, replicated input must agree with the single
/// CPU reference bootstrap coefficient-wise, within the floating point rounding tolerance.
///
/// Run at both batch sizes on either side of [`CG_VARIANT_MAX_BATCH_SIZE`], so the test does not
/// silently pin a single kernel variant.
#[test]
fn test_halfhalf_pbs128_tier1_gentle_params_matches_cpu_reference() {
    let fixture = Tier1Fixture::new();
    let cpu_out = fixture.cpu_reference();

    for batch_size in [8usize, 16usize] {
        let d_input = replicated_input(&fixture.lwe_in, &fixture.streams, batch_size);
        let gpu_out = run_halfhalf_batch(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &d_input,
            fixture.output_lwe_dimension,
            &fixture.streams,
        );

        for lane in 0..batch_size {
            let lane_out = LweCiphertext::from_container(
                gpu_out.get(lane).into_container().to_vec(),
                gpu_out.ciphertext_modulus(),
            );
            assert_bootstrap_outputs_close(
                &lane_out,
                &cpu_out,
                MAX_ABS_DIFF,
                &format!(
                    "halfhalf GPU bootstrap (batch size {batch_size}, lane {lane}) differs from \
                    the CPU reference"
                ),
            );
        }

        assert_determinism_at_batch_size(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &d_input,
            fixture.output_lwe_dimension,
            &fixture.streams,
            &gpu_out,
            &format!("halfhalf PBS128 tier1 gentle params, batch size {batch_size}"),
        );
    }

    if !is_sanitizer_run() {
        assert_batch_size_independent(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &fixture.lwe_in,
            fixture.output_lwe_dimension,
            &fixture.streams,
            // `[1, 2]`, not `[1, CG_VARIANT_MAX_BATCH_SIZE]`: the cooperative-groups kernel also
            // needs an occupancy probe to succeed, which at batch 8 needs 72 resident blocks
            // against 18 at batch 2 — a device with less capacity than this 4090 could fall back
            // to the default kernel at 8 and turn this into a cross-variant comparison. Batch 2
            // is the smallest size that still exercises more than one lane.
            &[1, 2],
            "halfhalf PBS128 tier1 gentle params, cooperative-groups variant",
        );
        assert_batch_size_independent(
            &fixture.gpu_bsk,
            &fixture.d_accumulator,
            &fixture.lwe_in,
            fixture.output_lwe_dimension,
            &fixture.streams,
            &[CG_VARIANT_MAX_BATCH_SIZE + 1, 16],
            "halfhalf PBS128 tier1 gentle params, default variant",
        );
    }
}
