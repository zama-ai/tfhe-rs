use super::super::test::TestResources;
use super::assert_gpu_determinism;
use crate::core_crypto::commons::test_tools::{check_both_ratio_under, new_random_generator};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{CudaStreams, GpuIndex};
use crate::core_crypto::prelude::*;
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::cell::RefCell;
use tfhe_cuda_backend::bindings::{
    cuda_centered_modulus_switch_64_async, cuda_centered_modulus_switch_cooperative_64_async,
    cuda_modulus_switch_64_async,
};

thread_local! {
    static TEST_RESOURCES: RefCell<TestResources> = {
        RefCell::new(TestResources::new())
    }
}

fn decrypt_cuda_modulus_switched_lwe_ciphertext<Scalar, KeyCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    d_lwe_ciphertext: &CudaLweCiphertextList<Scalar>,
    log_modulus: CiphertextModulusLog,
    stream: &CudaStreams,
) -> Scalar
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
{
    let lwe_ciphertext = d_lwe_ciphertext.into_lwe_ciphertext(stream);

    assert_eq!(
        lwe_ciphertext.lwe_size(),
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size(),
        lwe_secret_key.lwe_dimension()
    );

    let mask = lwe_ciphertext.get_mask();

    let body = lwe_ciphertext.get_body().data;

    let mask_key_dot_product = mask
        .as_ref()
        .iter()
        .zip(lwe_secret_key.as_ref().iter())
        .fold(Scalar::ZERO, |acc, (left, &right)| {
            acc.wrapping_add(left.wrapping_mul(right))
        });

    body.wrapping_sub(mask_key_dot_product) % (Scalar::ONE << log_modulus.0)
}

// The cooperative correction splits the mask over every thread of the block, so
// its result depends on the block shape it is called in
#[derive(Clone, Copy, Debug)]
pub struct CooperativeBlockShape {
    dim_x: u32,
    dim_y: u32,
}

// The block of the specialized 2_2 throughput PBS
const THROUGHPUT_PBS_BLOCK_SHAPE: CooperativeBlockShape = CooperativeBlockShape {
    dim_x: 64,
    dim_y: 2,
};

// A plain 1D block, as pbs128 launches (polynomial_size / opt, 1, 1), so 512
// threads for N = 2048
const GENERIC_BLOCK_SHAPE: CooperativeBlockShape = CooperativeBlockShape {
    dim_x: 512,
    dim_y: 1,
};

pub enum ModulusSwitchAlgorithm {
    Regular,
    Centered,
    // Centered, with the body correction computed by the block-cooperative
    // reduction instead of a single thread
    CenteredCooperative(CooperativeBlockShape),
}

fn cuda_apply_modulus_switch(
    ms: &ModulusSwitchAlgorithm,
    d_lwe_output: &mut CudaLweCiphertextList<u64>,
    d_lwe_input: &CudaLweCiphertextList<u64>,
    log_modulus: CiphertextModulusLog,
    stream: &CudaStreams,
) {
    let lwe_dimension = d_lwe_input.lwe_dimension();

    unsafe {
        match ms {
            ModulusSwitchAlgorithm::Regular => cuda_modulus_switch_64_async(
                stream.ptr[0],
                stream.gpu_indexes[0].get(),
                d_lwe_output.0.d_vec.as_mut_c_ptr(0),
                d_lwe_input.0.d_vec.as_c_ptr(0),
                lwe_dimension.to_lwe_size().0 as u32,
                log_modulus.0 as u32,
            ),
            ModulusSwitchAlgorithm::Centered => cuda_centered_modulus_switch_64_async(
                stream.ptr[0],
                stream.gpu_indexes[0].get(),
                d_lwe_output.0.d_vec.as_mut_c_ptr(0),
                d_lwe_input.0.d_vec.as_c_ptr(0),
                lwe_dimension.0 as u32,
                log_modulus.0 as u32,
            ),
            ModulusSwitchAlgorithm::CenteredCooperative(block_shape) => {
                cuda_centered_modulus_switch_cooperative_64_async(
                    stream.ptr[0],
                    stream.gpu_indexes[0].get(),
                    d_lwe_output.0.d_vec.as_mut_c_ptr(0),
                    d_lwe_input.0.d_vec.as_c_ptr(0),
                    lwe_dimension.0 as u32,
                    log_modulus.0 as u32,
                    block_shape.dim_x,
                    block_shape.dim_y,
                )
            }
        }
    }
}

#[test]
fn check_centered_modulus_switch_is_centered() {
    let number_loops = 1_000_000;

    let max_ratio = 1.05;

    // lwe_ciphertext_modulus_switch does do half case correction so should fail this check
    assert!(!check_cuda_modulus_switch_is_centered(
        &ModulusSwitchAlgorithm::Regular,
        number_loops,
        max_ratio,
    ));

    assert!(check_cuda_modulus_switch_is_centered(
        &ModulusSwitchAlgorithm::Centered,
        number_loops,
        max_ratio,
    ));
}

fn check_cuda_modulus_switch_is_centered(
    ms: &ModulusSwitchAlgorithm,
    number_loops: usize,
    max_ratio: f64,
) -> bool {
    let lwe_dimension = LweDimension(800);

    let lwe_noise_distribution: DynamicDistribution<u64> =
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.));

    let ciphertext_modulus = CiphertextModulus::new_native();

    let log_modulus = CiphertextModulusLog(12);

    let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

    for sk_bit in sk.as_mut().iter_mut().step_by(2) {
        *sk_bit = 1;
    }

    // low value increases p_error which helps verify p_error_left == p_error_right
    let half_redundancy = 1;

    let num_streams = 4;
    assert_eq!(
        number_loops % num_streams,
        0,
        "number_loops must be divisible by num_streams"
    );
    let num_loops_per_stream = number_loops / num_streams;

    let vec_stream = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(0)))
        .collect::<Vec<_>>();

    let (lut_application_left_error, lut_application_right_error): (Vec<bool>, Vec<bool>) = (0
        ..num_streams)
        .into_par_iter()
        .flat_map(|i| {
            let local_stream = vec_stream[i % num_streams].clone();
            let mut d_lwe_output = CudaLweCiphertextList::new(
                lwe_dimension,
                LweCiphertextCount(1),
                ciphertext_modulus,
                &local_stream,
            );

            // A vector to collect results from the inner loop
            let mut results = Vec::with_capacity(num_loops_per_stream);

            // There is no parallelization of operations running on the same stream, so we use a
            // sequential iterator
            for _ in 0..num_loops_per_stream {
                let input_lwe = TEST_RESOURCES.with(|rsc| {
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &sk,
                        Plaintext(0),
                        lwe_noise_distribution,
                        ciphertext_modulus,
                        &mut rsc.borrow_mut().encryption_random_generator,
                    )
                });

                let d_lwe_input =
                    CudaLweCiphertextList::from_lwe_ciphertext(&input_lwe, &local_stream);
                cuda_apply_modulus_switch(
                    ms,
                    &mut d_lwe_output,
                    &d_lwe_input,
                    log_modulus,
                    &local_stream,
                );
                let lut_index = decrypt_cuda_modulus_switched_lwe_ciphertext(
                    &sk,
                    &d_lwe_output,
                    log_modulus,
                    &local_stream,
                );

                // lut indexes are modular (modulo 2^log_modulus)
                // (modulus = 2 * polynomial_size)
                // We do:
                // - map [0, 2^log_modulus[ to [0, 2^64[
                // - go from unsigned to signed modulo 2^64 (with into_signed)
                // - map back [0, 2^64[ to [0, 2^log_modulus[
                // In the end, we have a signed index
                let lut_index_signed =
                    (lut_index << (64 - log_modulus.0)).into_signed() >> (64 - log_modulus.0);

                // The lut case goes from [-half_redundancy, half_redundancy[
                // It contains redundancy(=2*half_redundancy) elements and is not centered
                // around 0
                let lut_application_left_error = lut_index_signed < -half_redundancy;

                let lut_application_right_error = half_redundancy <= lut_index_signed;
                results.push((lut_application_left_error, lut_application_right_error));
            }

            results
        })
        .unzip();

    assert_eq!(
        lut_application_left_error.len() + lut_application_right_error.len(),
        2 * number_loops,
        "incorrect number of iterations"
    );
    let left_error_count = lut_application_left_error
        .iter()
        .filter(|error| **error)
        .count();

    let right_error_count = lut_application_right_error
        .iter()
        .filter(|error| **error)
        .count();

    let p_left_error = left_error_count as f64 / number_loops as f64;

    let p_right_error = right_error_count as f64 / number_loops as f64;

    println!("p_left_error={p_left_error}, p_right_error={p_right_error}");

    check_both_ratio_under(p_left_error, p_right_error, max_ratio)
}

#[test]
fn compare_cpu_and_gpu_centered_modulus_switch() {
    let lwe_dimension = LweDimension(800);

    let lwe_noise_distribution: DynamicDistribution<u64> =
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.));

    let ciphertext_modulus = CiphertextModulus::new_native();

    let log_modulus = CiphertextModulusLog(12);

    let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

    for sk_bit in sk.as_mut().iter_mut().step_by(2) {
        *sk_bit = 1;
    }

    let streams = CudaStreams::new_multi_gpu();

    // CPU
    let lwe = TEST_RESOURCES.with(|rsc| {
        allocate_and_encrypt_new_lwe_ciphertext(
            &sk,
            Plaintext(0),
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut rsc.borrow_mut().encryption_random_generator,
        )
    });

    let msed_lwe: LazyStandardModulusSwitchedLweCiphertext<u64, u64, &[u64]> =
        lwe_ciphertext_centered_binary_modulus_switch(lwe.as_view(), log_modulus);
    let mut msed_container = msed_lwe.mask().collect_vec();
    msed_container.push(msed_lwe.body());

    // GPU
    let d_lwe_input = CudaLweCiphertextList::from_lwe_ciphertext(&lwe, &streams);
    let mut d_lwe_output = CudaLweCiphertextList::new(
        lwe_dimension,
        LweCiphertextCount(1),
        ciphertext_modulus,
        &streams,
    );

    unsafe {
        cuda_centered_modulus_switch_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            d_lwe_output.0.d_vec.as_mut_c_ptr(0),
            d_lwe_input.0.d_vec.as_c_ptr(0),
            d_lwe_input.lwe_dimension().0 as u32,
            log_modulus.0 as u32,
        );
    }

    let converted_gpu_ct = d_lwe_output.into_lwe_ciphertext(&streams);

    // Determinism check
    let mut d_lwe_output_bis = CudaLweCiphertextList::new(
        lwe_dimension,
        LweCiphertextCount(1),
        ciphertext_modulus,
        &streams,
    );
    unsafe {
        cuda_centered_modulus_switch_64_async(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            d_lwe_output_bis.0.d_vec.as_mut_c_ptr(0),
            d_lwe_input.0.d_vec.as_c_ptr(0),
            d_lwe_input.lwe_dimension().0 as u32,
            log_modulus.0 as u32,
        );
    }
    assert_gpu_determinism(
        converted_gpu_ct.as_ref(),
        d_lwe_output_bis.into_lwe_ciphertext(&streams).as_ref(),
        "cuda_centered_modulus_switch_64",
    );

    assert_eq!(msed_container, converted_gpu_ct.into_container());
}

// Relative to the 128 and 512 threads blocks: smaller than both, exact multiple
// of both, then two multiples of neither. All below 1023, the sequential kernel
// we compare against launches lwe_dimension + 1 threads in a single block
const COOPERATIVE_TEST_LWE_DIMENSIONS: [usize; 4] = [100, 512, 742, 800];

fn cuda_centered_modulus_switch(
    ms: &ModulusSwitchAlgorithm,
    lwe: &LweCiphertextOwned<u64>,
    log_modulus: CiphertextModulusLog,
    streams: &CudaStreams,
) -> Vec<u64> {
    let d_lwe_input = CudaLweCiphertextList::from_lwe_ciphertext(lwe, streams);
    let mut d_lwe_output = CudaLweCiphertextList::new(
        lwe.lwe_size().to_lwe_dimension(),
        LweCiphertextCount(1),
        lwe.ciphertext_modulus(),
        streams,
    );

    cuda_apply_modulus_switch(ms, &mut d_lwe_output, &d_lwe_input, log_modulus, streams);

    d_lwe_output.into_lwe_ciphertext(streams).into_container()
}

// The cooperative correction is a second implementation of the centered modulus
// switch, the one the PBS runs, and a wrong correction there is hidden by the
// decoding of the PBS output. So we check it on its own, against the CPU and
// against the sequential GPU kernel.
fn check_cuda_cooperative_centered_modulus_switch(
    block_shape: CooperativeBlockShape,
    lwe_dimension: LweDimension,
) {
    const NB_TESTS: usize = 10;

    let lwe_noise_distribution: DynamicDistribution<u64> =
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.000007069849454709433));

    let ciphertext_modulus = CiphertextModulus::new_native();

    let log_modulus = CiphertextModulusLog(12);

    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));

    let sk = TEST_RESOURCES.with(|rsc| {
        allocate_and_generate_new_binary_lwe_secret_key(
            lwe_dimension,
            &mut rsc.borrow_mut().secret_random_generator,
        )
    });

    let mut random_generator = new_random_generator();

    let cooperative = ModulusSwitchAlgorithm::CenteredCooperative(block_shape);

    for _ in 0..NB_TESTS {
        // The correction depends on the mask and the body only, vary both
        let plaintext = Plaintext(random_generator.random_uniform::<u64>());

        let lwe = TEST_RESOURCES.with(|rsc| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &sk,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut rsc.borrow_mut().encryption_random_generator,
            )
        });

        // CPU reference
        let msed_lwe: LazyStandardModulusSwitchedLweCiphertext<u64, u64, &[u64]> =
            lwe_ciphertext_centered_binary_modulus_switch(lwe.as_view(), log_modulus);
        let mut cpu_container = msed_lwe.mask().collect_vec();
        cpu_container.push(msed_lwe.body());

        // GPU, single thread correction
        let sequential_container = cuda_centered_modulus_switch(
            &ModulusSwitchAlgorithm::Centered,
            &lwe,
            log_modulus,
            &streams,
        );

        // GPU, block-cooperative correction
        let cooperative_container =
            cuda_centered_modulus_switch(&cooperative, &lwe, log_modulus, &streams);

        // Determinism check
        let cooperative_container_bis =
            cuda_centered_modulus_switch(&cooperative, &lwe, log_modulus, &streams);

        assert_gpu_determinism(
            &cooperative_container,
            &cooperative_container_bis,
            "cuda_centered_modulus_switch_cooperative_64",
        );

        assert_eq!(
            cpu_container, cooperative_container,
            "cooperative centered modulus switch in a ({}, {}, 1) block differs from the CPU \
            implementation for lwe_dimension={}",
            block_shape.dim_x, block_shape.dim_y, lwe_dimension.0,
        );

        assert_eq!(
            sequential_container, cooperative_container,
            "cooperative centered modulus switch in a ({}, {}, 1) block differs from the \
            sequential GPU implementation for lwe_dimension={}",
            block_shape.dim_x, block_shape.dim_y, lwe_dimension.0,
        );
    }
}

#[test]
fn compare_cpu_and_gpu_cooperative_centered_modulus_switch_throughput_pbs_block() {
    for lwe_dimension in COOPERATIVE_TEST_LWE_DIMENSIONS {
        check_cuda_cooperative_centered_modulus_switch(
            THROUGHPUT_PBS_BLOCK_SHAPE,
            LweDimension(lwe_dimension),
        );
    }
}

#[test]
fn compare_cpu_and_gpu_cooperative_centered_modulus_switch_generic_block() {
    for lwe_dimension in COOPERATIVE_TEST_LWE_DIMENSIONS {
        check_cuda_cooperative_centered_modulus_switch(
            GENERIC_BLOCK_SHAPE,
            LweDimension(lwe_dimension),
        );
    }
}
