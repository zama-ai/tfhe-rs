use super::super::test::TestResources;
use crate::core_crypto::commons::test_tools::check_both_ratio_under;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{CudaStreams, GpuIndex};
use crate::core_crypto::prelude::*;
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::cell::RefCell;
use tfhe_cuda_backend::bindings::{
    cuda_centered_modulus_switch_64_async, cuda_modulus_switch_64_async,
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

pub enum ModulusSwitchAlgorithm {
    Regular,
    Centered,
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
                unsafe {
                    match ms {
                        ModulusSwitchAlgorithm::Regular => cuda_modulus_switch_64_async(
                            local_stream.ptr[0],
                            local_stream.gpu_indexes[0].get(),
                            d_lwe_output.0.d_vec.as_mut_c_ptr(0),
                            d_lwe_input.0.d_vec.as_c_ptr(0),
                            d_lwe_input.lwe_dimension().to_lwe_size().0 as u32,
                            log_modulus.0 as u32,
                        ),
                        ModulusSwitchAlgorithm::Centered => cuda_centered_modulus_switch_64_async(
                            local_stream.ptr[0],
                            local_stream.gpu_indexes[0].get(),
                            d_lwe_output.0.d_vec.as_mut_c_ptr(0),
                            d_lwe_input.0.d_vec.as_c_ptr(0),
                            d_lwe_input.lwe_dimension().0 as u32,
                            log_modulus.0 as u32,
                        ),
                    }
                }
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

    assert_eq!(msed_container, converted_gpu_ct.into_container());
}
