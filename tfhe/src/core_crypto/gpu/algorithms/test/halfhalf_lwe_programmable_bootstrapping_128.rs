//! Differential tests for the "halfhalf" (half-product plus half-rotate) 128-bit GPU
//! programmable bootstrap, comparing it against the CPU reference implemented in
//! `core_crypto::fft_impl::fft128::crypto::bootstrap_half_product_half_rotate`.
//!
//! Gadget decomposition is a step function: as long as the CPU and GPU floating point
//! accumulations round to the same digit at every decomposition level, the two outputs agree up
//! to that floating point rounding difference. Once the accumulated difference exceeds one gadget
//! step at some level, the two sides pick different digits there, and the difference from then on
//! is genuine decomposition noise rather than floating point rounding. This is why the tests below
//! are split in two tiers: [`tier1`] uses gentler decomposition parameters where the accumulated
//! difference never approaches a gadget step, so the comparison stays exact (coefficient-wise,
//! reusing the tolerance the CPU-only half-product tests already use for the same reason). At the
//! production parameters in [`tier2`] the finest gadget step is only about 2^7 above the
//! accumulated floating point difference, so a coefficient-wise comparison would fail on a correct
//! implementation; [`tier2`] instead bounds the *statistics* of the noise the two sides add.

mod tier1;
mod tier2;

use super::{batched_input, is_sanitizer_run, replicated_input};
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::CudaHalfhalfBootstrapKey;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{
    cuda_programmable_bootstrap_128_halfhalf_lwe_ciphertext, CudaStreams,
};
use crate::core_crypto::prelude::*;

/// Runs the halfhalf GPU bootstrap on `input` and returns the host-side output list.
fn run_halfhalf_batch(
    gpu_bsk: &CudaHalfhalfBootstrapKey,
    accumulator: &CudaGlweCiphertextList<u128>,
    input: &CudaLweCiphertextList<u64>,
    output_lwe_dimension: LweDimension,
    streams: &CudaStreams,
) -> LweCiphertextList<Vec<u128>> {
    let batch_size = input.lwe_ciphertext_count();
    let mut d_output = CudaLweCiphertextList::new(
        output_lwe_dimension,
        batch_size,
        CiphertextModulus::<u128>::new_native(),
        streams,
    );
    cuda_programmable_bootstrap_128_halfhalf_lwe_ciphertext(
        input,
        &mut d_output,
        accumulator,
        gpu_bsk,
        streams,
    );
    d_output.to_lwe_ciphertext_list(streams)
}

/// Batch size at or below which the halfhalf scratch selects the cooperative-groups kernel; see
/// `programmable_bootstrap_classic_128_halfhalf.cuh`. Batch size alone is not sufficient: the
/// scratch also runs an occupancy probe (needing `max_level_count * (glwe_dimension + 1) *
/// num_samples` resident blocks) that must succeed, so a device with less capacity than this 4090
/// or an H100 can fall back to the default kernel below this boundary too. The two variants
/// accumulate in different orders, so tests that want to pin one flavor must stay on the same side
/// of this boundary *and* keep the batch small enough that the occupancy probe succeeds on every
/// device the suite runs on, and tests that want to exercise both variants must straddle it
/// explicitly.
const CG_VARIANT_MAX_BATCH_SIZE: usize = 8;

/// Asserts that every lane of `output`, run at `batch_size`, is bit-identical to every lane of a
/// second GPU run of the same size on the same input. Skipped under the sanitizer to keep each
/// test to a single kernel call, matching the convention the rest of this crate's PBS128 tests
/// follow.
fn assert_determinism_at_batch_size(
    gpu_bsk: &CudaHalfhalfBootstrapKey,
    accumulator: &CudaGlweCiphertextList<u128>,
    input: &CudaLweCiphertextList<u64>,
    output_lwe_dimension: LweDimension,
    streams: &CudaStreams,
    first_run: &LweCiphertextList<Vec<u128>>,
    operator: &str,
) {
    if is_sanitizer_run() {
        return;
    }
    let second_run = run_halfhalf_batch(gpu_bsk, accumulator, input, output_lwe_dimension, streams);
    super::assert_gpu_determinism(first_run.as_ref(), second_run.as_ref(), operator);
}

/// Asserts that bootstrapping the same input LWE ciphertext produces a bit-identical lane
/// whatever the batch size it is bootstrapped within, as long as every size stays on the same
/// side of [`CG_VARIANT_MAX_BATCH_SIZE`]. `sizes` must all be on the same side of that boundary;
/// straddling it would compare two different kernel accumulation orders and is expected to
/// differ, which is exactly what `pbs128_golden` avoids by never drawing a random batch size
/// across it.
fn assert_batch_size_independent(
    gpu_bsk: &CudaHalfhalfBootstrapKey,
    accumulator: &CudaGlweCiphertextList<u128>,
    lwe_in: &LweCiphertextOwned<u64>,
    output_lwe_dimension: LweDimension,
    streams: &CudaStreams,
    sizes: &[usize],
    operator: &str,
) {
    assert!(
        sizes
            .iter()
            .all(|&size| (size <= CG_VARIANT_MAX_BATCH_SIZE)
                == (sizes[0] <= CG_VARIANT_MAX_BATCH_SIZE)),
        "{operator}: sizes {sizes:?} must all stay on the same side of the \
        cooperative-groups/default kernel boundary ({CG_VARIANT_MAX_BATCH_SIZE})"
    );

    let mut reference: Option<Vec<u128>> = None;
    for &batch_size in sizes {
        let input = replicated_input(lwe_in, streams, batch_size);
        let output =
            run_halfhalf_batch(gpu_bsk, accumulator, &input, output_lwe_dimension, streams);
        let lwe_size = output_lwe_dimension.to_lwe_size();
        for lane in 0..batch_size {
            let lane_data = &output.as_ref()[lane * lwe_size.0..(lane + 1) * lwe_size.0];
            match &reference {
                None => reference = Some(lane_data.to_vec()),
                Some(reference) => assert_eq!(
                    reference.as_slice(),
                    lane_data,
                    "{operator}: lane {lane} of a batch of size {batch_size} differs from the \
                    reference lane, batch size must not change the per-lane result"
                ),
            }
        }
    }
}
