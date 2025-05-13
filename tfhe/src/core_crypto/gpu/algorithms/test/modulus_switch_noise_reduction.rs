use super::super::test::TestResources;
use crate::core_crypto::commons::test_tools::{check_both_ratio_under, mean, variance};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::{CudaStreams, CudaVec};
use crate::core_crypto::prelude::*;

use crate::core_crypto::gpu::GpuIndex;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::cell::RefCell;
use tfhe_cuda_backend::bindings::{
    cuda_improve_noise_modulus_switch_64, cuda_modulus_switch_inplace_64,
};

#[derive(Copy, Clone)]
struct MsNoiseReductionTestParams {
    pub lwe_dimension: LweDimension,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
    pub modulus_switch_zeros_count: LweCiphertextCount,
    pub bound: NoiseEstimationMeasureBound,
    pub r_sigma_factor: RSigmaFactor,
    pub input_variance: Variance,
    pub log_modulus: CiphertextModulusLog,
    pub expected_variance_improved: Variance,
}

const TEST_PARAM: MsNoiseReductionTestParams = MsNoiseReductionTestParams {
    lwe_dimension: LweDimension(918),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    ciphertext_modulus: CiphertextModulus::new_native(),
    modulus_switch_zeros_count: LweCiphertextCount(1449),
    bound: NoiseEstimationMeasureBound(288230376151711744_f64),
    r_sigma_factor: RSigmaFactor(13.179852282053789f64),
    log_modulus: PolynomialSize(2048).to_blind_rotation_input_modulus_log(),
    expected_variance_improved: Variance(1.40546154228955e-6),
    input_variance: Variance(2.63039184094559e-7f64),
};

thread_local! {
    static TEST_RESOURCES: RefCell<TestResources> = {
        RefCell::new(TestResources::new())
    }
}

fn round_mask_gpu(
    ct: &mut LweCiphertext<Vec<u64>>,
    d_ct: &mut CudaLweCiphertextList<u64>,
    log_modulus: CiphertextModulusLog,
    lwe_dimension: LweDimension,

    streams: &CudaStreams,
) {
    let shift_to_map_to_native = u64::BITS - log_modulus.0 as u32;

    unsafe {
        //Here i call it with lwe_dimension cause i don't want to change the body
        cuda_modulus_switch_inplace_64(
            streams.ptr[0],
            streams.gpu_indexes[0].get(),
            d_ct.0.d_vec.as_mut_c_ptr(0),
            lwe_dimension.0 as u32,
            log_modulus.0 as u32,
        );
    }
    streams.synchronize();
    let cpu_lwe_list = d_ct.to_lwe_ciphertext_list(streams);

    let mut ct_after_ms =
        LweCiphertext::from_container(cpu_lwe_list.into_container(), ct.ciphertext_modulus());

    for val in ct_after_ms.get_mut_mask().as_mut() {
        *val <<= shift_to_map_to_native;
    }

    *ct = ct_after_ms;
}

fn measure_noise_added_by_message_preserving_operation<C1, C2>(
    sk: &LweSecretKey<C1>,
    mut ct: LweCiphertext<C2>,
    message_preserving_operation: impl Fn(&mut LweCiphertext<C2>),
) -> f64
where
    C1: Container<Element = u64>,
    C2: ContainerMut<Element = u64>,
{
    let decrypted_before = decrypt_lwe_ciphertext(sk, &ct);

    message_preserving_operation(&mut ct);

    let decrypted_after = decrypt_lwe_ciphertext(sk, &ct);

    decrypted_after.0.wrapping_sub(decrypted_before.0) as i64 as f64
}

#[test]
fn check_noise_improve_modulus_switch_noise_test_param() {
    check_noise_improve_modulus_switch_noise(TEST_PARAM);
}

fn check_noise_improve_modulus_switch_noise(
    ms_noise_reduction_test_params: MsNoiseReductionTestParams,
) {
    let MsNoiseReductionTestParams {
        lwe_dimension,
        lwe_noise_distribution,
        ciphertext_modulus,
        modulus_switch_zeros_count,
        bound,
        r_sigma_factor,
        log_modulus,
        expected_variance_improved,
        input_variance,
    } = ms_noise_reduction_test_params;

    let number_loops = 100_000;

    let mut rsc = TestResources::new();

    let mut sk = LweSecretKeyOwned::new_empty_key(0, lwe_dimension);

    for sk_bit in sk.as_mut().iter_mut().step_by(2) {
        *sk_bit = 1;
    }

    let sk_average_bit: f64 =
        sk.as_view().into_container().iter().sum::<u64>() as f64 / sk.lwe_dimension().0 as f64;

    println!("sk_average_bit {sk_average_bit:.3}");

    let plaintext_list = PlaintextList::new(0, PlaintextCount(modulus_switch_zeros_count.0));

    let mut encryptions_of_zero = LweCiphertextList::new(
        0,
        lwe_dimension.to_lwe_size(),
        modulus_switch_zeros_count,
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext_list(
        &sk,
        &mut encryptions_of_zero,
        &plaintext_list,
        lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let num_blocks = 1;
    let lwe_indexes: Vec<u64> = (0..num_blocks).map(|x| x as u64).collect();
    let mut d_input_indexes = unsafe { CudaVec::<u64>::new_async(num_blocks, &streams, 0) };
    unsafe { d_input_indexes.copy_from_cpu_async(&lwe_indexes, &streams, 0) };

    let d_encryptions_of_zero = CudaLweCiphertextList::from_lwe_ciphertext_list(
        &encryptions_of_zero,
        &CudaStreams::new_single_gpu(GpuIndex::new(0)),
    );
    let num_streams = 16;
    let vec_streams = (0..num_streams)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();
    let (ms_errors, ms_errors_improved): (Vec<_>, Vec<_>) = (0..number_loops)
        .into_par_iter()
        .map(|index| {
            let stream_index = index % num_streams as usize;
            let local_stream = &vec_streams[stream_index];
            let lwe = TEST_RESOURCES.with(|rsc| {
                allocate_and_encrypt_new_lwe_ciphertext(
                    &sk,
                    Plaintext(0),
                    lwe_noise_distribution,
                    ciphertext_modulus,
                    &mut rsc.borrow_mut().encryption_random_generator,
                )
            });

            (
                measure_noise_added_by_message_preserving_operation(&sk, lwe.clone(), |ct| {
                    let mut d_ct = CudaLweCiphertextList::from_lwe_ciphertext(ct, local_stream);
                    round_mask_gpu(ct, &mut d_ct, log_modulus, lwe_dimension, local_stream);
                }),
                measure_noise_added_by_message_preserving_operation(&sk, lwe.clone(), |ct| {
                    let mut d_ct = CudaLweCiphertextList::from_lwe_ciphertext(ct, local_stream);
                    let d_ct_in = CudaLweCiphertextList::from_lwe_ciphertext(ct, local_stream);
                    let modulus = lwe.ciphertext_modulus().raw_modulus_float();
                    unsafe {
                        cuda_improve_noise_modulus_switch_64(
                            local_stream.ptr[0],
                            streams.gpu_indexes[0].get(),
                            d_ct.0.d_vec.as_mut_c_ptr(0),
                            d_ct_in.0.d_vec.as_c_ptr(0),
                            d_input_indexes.as_c_ptr(0),
                            d_encryptions_of_zero.0.d_vec.as_c_ptr(0),
                            lwe_dimension.to_lwe_size().0 as u32,
                            d_ct.lwe_ciphertext_count().0 as u32,
                            d_encryptions_of_zero.lwe_ciphertext_count().0 as u32,
                            input_variance.get_modular_variance(modulus).value,
                            r_sigma_factor.0,
                            bound.0,
                            log_modulus.0 as u32,
                        );
                    }

                    round_mask_gpu(ct, &mut d_ct, log_modulus, lwe_dimension, local_stream);
                }),
            )
        })
        .unzip();

    println!(
        "mean(&ms_errors)                     {}2^{:.2}",
        if mean(&ms_errors) > 0_f64 { "+" } else { "-" },
        mean(&ms_errors).abs().log2()
    );

    println!(
        "mean(&ms_errors_improved)            {}2^{:.2}",
        if mean(&ms_errors_improved) > 0_f64 {
            "+"
        } else {
            "-"
        },
        mean(&ms_errors_improved).abs().log2()
    );

    let base_variance = variance(&ms_errors).0;

    println!(
        "variance(&ms_errors),                    2^{:.2}",
        base_variance.log2(),
    );

    let variance_improved = variance(&ms_errors_improved).0;

    println!(
        "variance(&ms_errors_improved)            2^{:.2}, ratio: {:.3}",
        variance_improved.log2(),
        variance_improved / base_variance,
    );

    let modulus = ciphertext_modulus.raw_modulus_float();

    let expected_base_variance = {
        let lwe_dim = lwe_dimension.0 as f64;

        let poly_size = 2_f64.powi((log_modulus.0 - 1) as i32);

        (lwe_dim + 2.) * modulus * modulus / (96. * poly_size * poly_size) + (lwe_dim - 4.) / 48.
    };

    assert!(
        check_both_ratio_under(base_variance, expected_base_variance, 1.03_f64),
        "Expected {expected_base_variance}, got {base_variance}",
    );

    let expected_variance_improved = Variance(expected_variance_improved.0 - input_variance.0)
        .get_modular_variance(modulus)
        .value;

    assert!(
        check_both_ratio_under(variance_improved, expected_variance_improved, 1.03_f64),
        "Expected {expected_variance_improved}, got {variance_improved}",
    );
}
