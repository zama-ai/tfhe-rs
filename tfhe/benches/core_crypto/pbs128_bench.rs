#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{init_parameters_set, write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, Criterion};
use dyn_stack::PodStack;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::bootstrap_scratch;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};

fn pbs_128(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs128";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    type Scalar = u128;

    let lwe_dimension = LweDimension(879);
    let glwe_dimension = GlweDimension(2);
    let polynomial_size = PolynomialSize(2048);
    let lwe_noise_distribution = DynamicDistribution::new_t_uniform(46);
    let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
    let pbs_base_log = DecompositionBaseLog(32);
    let pbs_level = DecompositionLevelCount(3);
    let ciphertext_modulus = CiphertextModulus::new_native();

    let params_name = "PARAMS_SWITCH_SQUASH";

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let input_lwe_secret_key =
        LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        lwe_dimension,
        ciphertext_modulus,
    );
    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key,
        &output_glwe_secret_key,
        &mut bsk,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let mut fourier_bsk = Fourier128LweBootstrapKey::new(
        lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
    );
    convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk, &mut fourier_bsk);

    let message_modulus: Scalar = 1 << 4;

    let input_message: Scalar = 3;

    let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

    let plaintext = Plaintext(input_message * delta);

    let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
        Scalar::ONE,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        ciphertext_modulus,
    );

    let mut out_pbs_ct: LweCiphertext<Vec<Scalar>> = LweCiphertext::new(
        0,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = vec![
        0u8;
        bootstrap_scratch::<Scalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft
        )
        .unwrap()
        .unaligned_bytes_required()
    ];

    let id = format!("{bench_name}::{params_name}");
    bench_group.bench_function(&id, |b| {
        b.iter(|| {
            fourier_bsk.bootstrap(
                &mut out_pbs_ct,
                &lwe_ciphertext_in,
                &accumulator,
                fft,
                PodStack::new(&mut buffers),
            );
            black_box(&mut out_pbs_ct);
        });
    });

    let params_record = CryptoParametersRecord {
        lwe_dimension: Some(lwe_dimension),
        glwe_dimension: Some(glwe_dimension),
        polynomial_size: Some(polynomial_size),
        lwe_noise_distribution: Some(lwe_noise_distribution),
        glwe_noise_distribution: Some(glwe_noise_distribution),
        pbs_base_log: Some(pbs_base_log),
        pbs_level: Some(pbs_level),
        ciphertext_modulus: Some(ciphertext_modulus),
        ..Default::default()
    };

    let bit_size = (message_modulus as u32).ilog2();
    write_to_json(
        &id,
        params_record,
        params_name,
        "pbs",
        &OperatorType::Atomic,
        bit_size,
        vec![bit_size],
    );
}

#[cfg(feature = "gpu")]
mod cuda {
    use crate::utilities::{
        cuda_local_keys_core, cuda_local_streams_core, get_bench_type, throughput_num_threads,
        write_to_json, BenchmarkType, CpuKeys, CpuKeysBuilder, CryptoParametersRecord,
        CudaLocalKeys, OperatorType,
    };
    use criterion::{black_box, Criterion, Throughput};
    use rayon::prelude::*;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::{
        cuda_programmable_bootstrap_128_lwe_ciphertext, get_number_of_gpus, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::engine::ShortintEngine;
    use tfhe::shortint::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
        LweDimension, ModulusSwitchNoiseReductionParams, PolynomialSize,
    };
    use tfhe::shortint::server_key::ModulusSwitchNoiseReductionKey;

    fn cuda_pbs_128(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::pbs128";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        type Scalar = u128;

        let lwe_dimension = LweDimension(879);
        let glwe_dimension = GlweDimension(2);
        let polynomial_size = PolynomialSize(2048);
        let lwe_noise_distribution = DynamicDistribution::new_t_uniform(46);
        let lwe_noise_distribution_u128: DynamicDistribution<u128> =
            DynamicDistribution::new_t_uniform(46);
        let glwe_noise_distribution = DynamicDistribution::new_t_uniform(30);
        let pbs_base_log = DecompositionBaseLog(24);
        let pbs_level = DecompositionLevelCount(3);
        let ciphertext_modulus = CiphertextModulus::new_native();
        let ct_modulus_u64: CiphertextModulus<u64> = CiphertextModulus::new_native();

        let modulus_switch_noise_reduction_params = ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1449),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
            ms_input_variance: Variance(2.63039184094559E-7f64),
        };

        let params_name = "PARAMS_SWITCH_SQUASH";

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let input_lwe_secret_key =
            LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

        let input_lwe_secret_key_u128 = LweSecretKey::from_container(
            input_lwe_secret_key
                .as_ref()
                .iter()
                .copied()
                .map(|x| x as u128)
                .collect::<Vec<_>>(),
        );

        let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
            lwe_dimension,
            ciphertext_modulus,
        );

        let mut engine = ShortintEngine::new();
        let modulus_switch_noise_reduction_key = Some(ModulusSwitchNoiseReductionKey::new(
            modulus_switch_noise_reduction_params,
            &input_lwe_secret_key,
            &mut engine,
            CiphertextModulus::new_native(),
            lwe_noise_distribution,
        ));

        let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new().bootstrap_key(bsk).build();

        let message_modulus: Scalar = 1 << 4;
        let input_message: Scalar = 3;
        let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;
        let plaintext = Plaintext(input_message * delta);

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let streams = CudaStreams::new_multi_gpu();
                let gpu_keys = CudaLocalKeys::from_cpu_keys(
                    &cpu_keys,
                    modulus_switch_noise_reduction_key.as_ref(),
                    &streams,
                );

                let lwe_ciphertext_in: LweCiphertextOwned<Scalar> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key_u128,
                        plaintext,
                        lwe_noise_distribution_u128,
                        ciphertext_modulus,
                        &mut encryption_generator,
                    );
                let lwe_ciphertext_in_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &streams);

                let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
                    Scalar::ONE,
                    glwe_dimension.to_glwe_size(),
                    polynomial_size,
                    ciphertext_modulus,
                );
                let accumulator_gpu =
                    CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                let out_pbs_ct = LweCiphertext::new(
                    0,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    ciphertext_modulus,
                );
                let mut out_pbs_ct_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &streams);

                bench_id = format!("{bench_name}::{params_name}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            cuda_programmable_bootstrap_128_lwe_ciphertext(
                                &lwe_ciphertext_in_gpu,
                                &mut out_pbs_ct_gpu,
                                &accumulator_gpu,
                                LweCiphertextCount(1),
                                gpu_keys.bsk.as_ref().unwrap(),
                                &streams,
                            );
                            black_box(&mut out_pbs_ct_gpu);
                        })
                    });
                }
            }
            BenchmarkType::Throughput => {
                let gpu_keys_vec =
                    cuda_local_keys_core(&cpu_keys, modulus_switch_noise_reduction_key.as_ref());
                let gpu_count = get_number_of_gpus() as usize;

                bench_id = format!("{bench_name}::throughput::{params_name}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                let elements_per_stream = elements as usize / gpu_count;
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let local_streams = cuda_local_streams_core();

                        let plaintext_list =
                            PlaintextList::new(Scalar::ZERO, PlaintextCount(elements_per_stream));

                        let input_cts = (0..gpu_count)
                            .map(|i| {
                                let mut input_ct_list = LweCiphertextList::new(
                                    Scalar::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(elements_per_stream),
                                    ciphertext_modulus,
                                );

                                encrypt_lwe_ciphertext_list(
                                    &input_lwe_secret_key_u128,
                                    &mut input_ct_list,
                                    &plaintext_list,
                                    lwe_noise_distribution_u128,
                                    &mut encryption_generator,
                                );

                                CudaLweCiphertextList::from_lwe_ciphertext_list(
                                    &input_ct_list,
                                    &local_streams[i],
                                )
                            })
                            .collect::<Vec<_>>();

                        let accumulators = (0..gpu_count)
                            .map(|i| {
                                let accumulator = GlweCiphertextOwned::new(
                                    Scalar::ONE,
                                    glwe_dimension.to_glwe_size(),
                                    polynomial_size,
                                    ciphertext_modulus,
                                );
                                CudaGlweCiphertextList::from_glwe_ciphertext(
                                    &accumulator,
                                    &local_streams[i],
                                )
                            })
                            .collect::<Vec<_>>();

                        // Allocate the LweCiphertext to store the result of the PBS
                        let output_cts = (0..gpu_count)
                            .map(|i| {
                                let output_ct_list = LweCiphertextList::new(
                                    Scalar::ZERO,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(elements_per_stream),
                                    ciphertext_modulus,
                                );
                                CudaLweCiphertextList::from_lwe_ciphertext_list(
                                    &output_ct_list,
                                    &local_streams[i],
                                )
                            })
                            .collect::<Vec<_>>();

                        local_streams.iter().for_each(|stream| stream.synchronize());

                        (input_cts, output_cts, accumulators, local_streams)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(input_cts, mut output_cts, accumulators, local_streams)| {
                            (0..gpu_count)
                                .into_par_iter()
                                .zip(input_cts.par_iter())
                                .zip(output_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .zip(local_streams.par_iter())
                                .for_each(
                                    |((((i, input_ct), output_ct), accumulator), local_stream)| {
                                        cuda_programmable_bootstrap_128_lwe_ciphertext(
                                            input_ct,
                                            output_ct,
                                            accumulator,
                                            LweCiphertextCount(1),
                                            gpu_keys_vec[i].bsk.as_ref().unwrap(),
                                            local_stream,
                                        );
                                    },
                                )
                        },
                        criterion::BatchSize::SmallInput,
                    );
                });
            }
        };

        let params_record = CryptoParametersRecord {
            lwe_dimension: Some(lwe_dimension),
            glwe_dimension: Some(glwe_dimension),
            polynomial_size: Some(polynomial_size),
            lwe_noise_distribution: Some(lwe_noise_distribution),
            glwe_noise_distribution: Some(glwe_noise_distribution),
            pbs_base_log: Some(pbs_base_log),
            pbs_level: Some(pbs_level),
            ciphertext_modulus: Some(ct_modulus_u64),
            ..Default::default()
        };

        let bit_size = (message_modulus as u32).ilog2();
        write_to_json(
            &bench_id,
            params_record,
            params_name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }

    pub fn cuda_pbs128_group() {
        let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
        cuda_pbs_128(&mut criterion);
    }
}

#[cfg(feature = "gpu")]
use cuda::cuda_pbs128_group;

pub fn pbs128_group() {
    let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
    pbs_128(&mut criterion);
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    cuda_pbs128_group();
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    pbs128_group();
}
fn main() {
    init_parameters_set();

    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
