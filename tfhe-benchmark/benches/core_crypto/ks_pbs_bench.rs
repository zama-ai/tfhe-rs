use benchmark::params::{
    benchmark_parameters, multi_bit_benchmark_parameters_with_grouping, multi_bit_num_threads,
};
use benchmark::utilities::{
    get_bench_type, get_param_type, throughput_num_threads, write_to_json, BenchmarkType,
    CryptoParametersRecord, OperatorType, ParamType,
};
use criterion::{black_box, Criterion, Throughput};
use rayon::prelude::*;
use serde::Serialize;
use tfhe::core_crypto::prelude::*;

// TODO Refactor KS, PBS and KS-PBS benchmarks into a single generic function.
fn ks_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::ks_pbs";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in parameters.iter() {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &output_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Allocate a new LweCiphertext and encrypt our plaintext
                let input_ks_ct: LweCiphertextOwned<Scalar> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &output_lwe_secret_key,
                        Plaintext(Scalar::ONE),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );

                let mut output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                    Scalar::ZERO,
                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                let accumulator = GlweCiphertext::new(
                    Scalar::ZERO,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut output_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                let mut buffers = ComputationBuffers::new();

                let fft = Fft::new(fourier_bsk.polynomial_size());
                let fft = fft.as_view();

                buffers.resize(
                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                        fourier_bsk.glwe_size(),
                        fourier_bsk.polynomial_size(),
                        fft,
                    )
                    .unwrap()
                    .unaligned_bytes_required(),
                );

                bench_id = format!("{bench_name}::{name}");
                println!("{bench_id}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            keyswitch_lwe_ciphertext(
                                &ksk_big_to_small,
                                &input_ks_ct,
                                &mut output_ks_ct,
                            );
                            programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                &output_ks_ct,
                                &mut output_pbs_ct,
                                &accumulator.as_view(),
                                &fourier_bsk,
                                fft,
                                buffers.stack(),
                            );
                            black_box(&mut output_pbs_ct);
                        })
                    });
                }
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                println!("Number of elements: {elements}"); // DEBUG
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let fft = Fft::new(fourier_bsk.polynomial_size());

                    let setup_encrypted_values = || {
                        let input_ks_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &output_lwe_secret_key,
                                    Plaintext(Scalar::ONE),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator,
                                )
                            })
                            .collect::<Vec<LweCiphertextOwned<Scalar>>>();

                        let output_ks_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<LweCiphertextOwned<Scalar>>>();

                        let accumulators = (0..elements)
                            .map(|_| {
                                GlweCiphertext::new(
                                    Scalar::ZERO,
                                    params.glwe_dimension.unwrap().to_glwe_size(),
                                    params.polynomial_size.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // Allocate the LweCiphertext to store the result of the PBS
                        let output_pbs_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        let buffers = (0..elements)
                            .map(|_| {
                                let mut buffer = ComputationBuffers::new();

                                buffer.resize(
                                    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                                    fourier_bsk.glwe_size(),
                                    fourier_bsk.polynomial_size(),
                                    fft.as_view(),
                                )
                                .unwrap()
                                .unaligned_bytes_required(),
                            );

                                buffer
                            })
                            .collect::<Vec<_>>();

                        (
                            input_ks_cts,
                            output_ks_cts,
                            output_pbs_cts,
                            accumulators,
                            buffers,
                        )
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(
                            input_ks_cts,
                            mut output_ks_cts,
                            mut output_pbs_cts,
                            accumulators,
                            mut buffers,
                        )| {
                            input_ks_cts
                                .par_iter()
                                .zip(output_ks_cts.par_iter_mut())
                                .zip(output_pbs_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .zip(buffers.par_iter_mut())
                                .for_each(
                                    |(
                                        (
                                            ((input_ks_ct, output_ks_ct), output_pbs_ct),
                                            accumulator,
                                        ),
                                        buffer,
                                    )| {
                                        keyswitch_lwe_ciphertext(
                                            &ksk_big_to_small,
                                            input_ks_ct,
                                            output_ks_ct,
                                        );
                                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                            output_ks_ct,
                                            output_pbs_ct,
                                            &accumulator.as_view(),
                                            &fourier_bsk,
                                            fft.as_view(),
                                            buffer.stack(),
                                        );
                                    },
                                )
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        }

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &bench_id,
            *params,
            name,
            "ks-pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn multi_bit_ks_pbs<
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Sync + Serialize,
>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    deterministic_pbs: bool,
) {
    let bench_name = if deterministic_pbs {
        "core_crypto::multi_bit_deterministic_ks_pbs"
    } else {
        "core_crypto::multi_bit_ks_pbs"
    };
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params, grouping_factor) in parameters.iter() {
        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &output_lwe_secret_key,
            &input_lwe_secret_key,
            params.ks_base_log.unwrap(),
            params.ks_level.unwrap(),
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let multi_bit_bsk = FourierLweMultiBitBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            *grouping_factor,
        );

        let thread_count = multi_bit_num_threads(
            params.message_modulus.unwrap(),
            params.carry_modulus.unwrap(),
            grouping_factor.0,
        )
        .unwrap() as usize;

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Allocate a new LweCiphertext and encrypt our plaintext
                let input_ks_ct: LweCiphertextOwned<Scalar> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &output_lwe_secret_key,
                        Plaintext(Scalar::ONE),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );

                let mut output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                    Scalar::ZERO,
                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                let accumulator = GlweCiphertext::new(
                    Scalar::ZERO,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut output_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                bench_id = format!("{bench_name}::{name}::parallelized");
                println!("{bench_id}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        keyswitch_lwe_ciphertext(
                            &ksk_big_to_small,
                            &input_ks_ct,
                            &mut output_ks_ct,
                        );
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &output_ks_ct,
                            &mut output_pbs_ct,
                            &accumulator.as_view(),
                            &multi_bit_bsk,
                            ThreadCount(thread_count),
                            deterministic_pbs,
                        );
                        black_box(&mut output_pbs_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                println!("Number of elements: {elements}"); // DEBUG
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let input_ks_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &output_lwe_secret_key,
                                    Plaintext(Scalar::ONE),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator,
                                )
                            })
                            .collect::<Vec<LweCiphertextOwned<Scalar>>>();

                        let output_ks_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<LweCiphertextOwned<Scalar>>>();

                        let accumulators = (0..elements)
                            .map(|_| {
                                GlweCiphertext::new(
                                    Scalar::ZERO,
                                    params.glwe_dimension.unwrap().to_glwe_size(),
                                    params.polynomial_size.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // Allocate the LweCiphertext to store the result of the PBS
                        let output_pbs_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        (input_ks_cts, output_ks_cts, output_pbs_cts, accumulators)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(input_ks_cts, mut output_ks_cts, mut output_pbs_cts, accumulators)| {
                            input_ks_cts
                                .par_iter()
                                .zip(output_ks_cts.par_iter_mut())
                                .zip(output_pbs_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .for_each(
                                    |(
                                        ((input_ks_ct, output_ks_ct), output_pbs_ct),
                                        accumulator,
                                    )| {
                                        keyswitch_lwe_ciphertext(
                                            &ksk_big_to_small,
                                            input_ks_ct,
                                            output_ks_ct,
                                        );
                                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                                            output_ks_ct,
                                            output_pbs_ct,
                                            &accumulator.as_view(),
                                            &multi_bit_bsk,
                                            ThreadCount(thread_count),
                                            deterministic_pbs,
                                        );
                                    },
                                )
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        };

        let bit_size = params.message_modulus.unwrap().ilog2();
        write_to_json(
            &bench_id,
            *params,
            name,
            "ks-pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

#[cfg(feature = "gpu")]
mod cuda {
    use super::{benchmark_parameters, multi_bit_benchmark_parameters_with_grouping};
    use benchmark::utilities::{
        cuda_local_keys_core, cuda_local_streams_core, get_bench_type, throughput_num_threads,
        write_to_json, BenchmarkType, CpuKeys, CpuKeysBuilder, CryptoParametersRecord, CudaIndexes,
        CudaLocalKeys, OperatorType, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE,
    };
    use criterion::{black_box, Criterion, Throughput};
    use rayon::prelude::*;
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::{
        cuda_keyswitch_lwe_ciphertext, cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, get_number_of_gpus, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;

    fn cuda_ks_pbs<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64> + Serialize>(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::ks_pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        for (name, params) in parameters.iter() {
            if params.polynomial_size.unwrap().0 > GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE {
                println!("[WARNING] polynomial size is too large for parameters set '{}' (max: {}, got: {})", name, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE, params.polynomial_size.unwrap().0);
                continue;
            }

            // Create the LweSecretKey
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );
            let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
                allocate_and_generate_new_binary_glwe_secret_key(
                    params.glwe_dimension.unwrap(),
                    params.polynomial_size.unwrap(),
                    &mut secret_generator,
                );
            let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &output_lwe_secret_key,
                &input_lwe_secret_key,
                params.ks_base_log.unwrap(),
                params.ks_level.unwrap(),
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

            let bsk = LweBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );

            let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new()
                .keyswitch_key(ksk_big_to_small)
                .bootstrap_key(bsk)
                .build();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    // Allocate a new LweCiphertext and encrypt our plaintext
                    let input_ks_ct = allocate_and_encrypt_new_lwe_ciphertext(
                        &output_lwe_secret_key,
                        Plaintext(Scalar::ZERO),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );
                    let input_ks_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&input_ks_ct, &streams);

                    let output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                        Scalar::ZERO,
                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut output_ks_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&output_ks_ct, &streams);

                    let accumulator = GlweCiphertext::new(
                        Scalar::ZERO,
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let accumulator_gpu =
                        CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                    // Allocate the LweCiphertext to store the result of the PBS
                    let output_pbs_ct = LweCiphertext::new(
                        Scalar::ZERO,
                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut output_pbs_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&output_pbs_ct, &streams);

                    let h_indexes = [Scalar::ZERO];
                    let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    {
                        bench_group.bench_function(&bench_id, |b| {
                            b.iter(|| {
                                cuda_keyswitch_lwe_ciphertext(
                                    gpu_keys.ksk.as_ref().unwrap(),
                                    &input_ks_ct_gpu,
                                    &mut output_ks_ct_gpu,
                                    &cuda_indexes.d_input,
                                    &cuda_indexes.d_output,
                                    &streams,
                                );
                                cuda_programmable_bootstrap_lwe_ciphertext(
                                    &output_ks_ct_gpu,
                                    &mut output_pbs_ct_gpu,
                                    &accumulator_gpu,
                                    &cuda_indexes.d_lut,
                                    &cuda_indexes.d_output,
                                    &cuda_indexes.d_input,
                                    gpu_keys.bsk.as_ref().unwrap(),
                                    &streams,
                                );
                                black_box(&mut output_pbs_ct_gpu);
                            })
                        });
                    }
                }
                BenchmarkType::Throughput => {
                    let gpu_keys_vec = cuda_local_keys_core(&cpu_keys, None);
                    let gpu_count = get_number_of_gpus() as usize;

                    bench_id = format!("{bench_name}::throughput::{name}");
                    println!("{bench_id}");
                    let blocks: usize = 1;
                    let elements = throughput_num_threads(blocks, 1);
                    let elements_per_stream = elements as usize / gpu_count;
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams_core();

                            let plaintext_list = PlaintextList::new(
                                Scalar::ZERO,
                                PlaintextCount(elements_per_stream),
                            );

                            let input_ks_cts = (0..gpu_count)
                                .map(|i| {
                                    let mut input_ks_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    encrypt_lwe_ciphertext_list(
                                        &output_lwe_secret_key,
                                        &mut input_ks_list,
                                        &plaintext_list,
                                        params.lwe_noise_distribution.unwrap(),
                                        &mut encryption_generator,
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &input_ks_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let output_ks_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_ks_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_ks_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let accumulators = (0..gpu_count)
                                .map(|i| {
                                    let accumulator = GlweCiphertext::new(
                                        Scalar::ZERO,
                                        params.glwe_dimension.unwrap().to_glwe_size(),
                                        params.polynomial_size.unwrap(),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaGlweCiphertextList::from_glwe_ciphertext(
                                        &accumulator,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            // Allocate the LweCiphertext to store the result of the PBS
                            let output_pbs_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_pbs_ct = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_pbs_ct,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let h_indexes = (0..(elements / gpu_count as u64))
                                .map(CastFrom::cast_from)
                                .collect::<Vec<_>>();
                            let cuda_indexes_vec = (0..gpu_count)
                                .map(|i| CudaIndexes::new(&h_indexes, &local_streams[i], 0))
                                .collect::<Vec<_>>();
                            local_streams.iter().for_each(|stream| stream.synchronize());

                            (
                                input_ks_cts,
                                output_ks_cts,
                                output_pbs_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(
                                input_ks_cts,
                                mut output_ks_cts,
                                mut output_pbs_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_ks_cts.par_iter())
                                    .zip(output_ks_cts.par_iter_mut())
                                    .zip(output_pbs_cts.par_iter_mut())
                                    .zip(accumulators.par_iter())
                                    .zip(local_streams.par_iter())
                                    .for_each(
                                        |(
                                            (
                                                (((i, input_ks_ct), output_ks_ct), output_pbs_ct),
                                                accumulator,
                                            ),
                                            local_stream,
                                        )| {
                                            cuda_keyswitch_lwe_ciphertext(
                                                gpu_keys_vec[i].ksk.as_ref().unwrap(),
                                                input_ks_ct,
                                                output_ks_ct,
                                                &cuda_indexes_vec[i].d_input,
                                                &cuda_indexes_vec[i].d_output,
                                                local_stream,
                                            );
                                            cuda_programmable_bootstrap_lwe_ciphertext(
                                                output_ks_ct,
                                                output_pbs_ct,
                                                accumulator,
                                                &cuda_indexes_vec[i].d_lut,
                                                &cuda_indexes_vec[i].d_output,
                                                &cuda_indexes_vec[i].d_input,
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

            let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
            write_to_json(
                &bench_id,
                *params,
                name,
                "ks-pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_multi_bit_ks_pbs<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64> + Default + Serialize + Sync,
    >(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    ) {
        let bench_name = "core_crypto::cuda::multi_bit_ks_pbs";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        for (name, params, grouping_factor) in parameters.iter() {
            if params.polynomial_size.unwrap().0 > GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE {
                println!("[WARNING] polynomial size is too large for parameters set '{}' (max: {}, got: {})", name, GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE, params.polynomial_size.unwrap().0);
                continue;
            }

            // Create the LweSecretKey
            let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension.unwrap(),
                &mut secret_generator,
            );
            let output_glwe_secret_key: GlweSecretKeyOwned<Scalar> =
                allocate_and_generate_new_binary_glwe_secret_key(
                    params.glwe_dimension.unwrap(),
                    params.polynomial_size.unwrap(),
                    &mut secret_generator,
                );
            let output_lwe_secret_key = output_glwe_secret_key.into_lwe_secret_key();

            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &output_lwe_secret_key,
                &input_lwe_secret_key,
                params.ks_base_log.unwrap(),
                params.ks_level.unwrap(),
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

            let multi_bit_bsk = LweMultiBitBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                *grouping_factor,
                params.ciphertext_modulus.unwrap(),
            );

            let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new()
                .keyswitch_key(ksk_big_to_small)
                .multi_bit_bootstrap_key(multi_bit_bsk)
                .build();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    // Allocate a new LweCiphertext and encrypt our plaintext
                    let input_ks_ct = allocate_and_encrypt_new_lwe_ciphertext(
                        &output_lwe_secret_key,
                        Plaintext(Scalar::ZERO),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );
                    let input_ks_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&input_ks_ct, &streams);

                    let output_ks_ct: LweCiphertextOwned<Scalar> = LweCiphertext::new(
                        Scalar::ZERO,
                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut output_ks_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&output_ks_ct, &streams);

                    let accumulator = GlweCiphertext::new(
                        Scalar::ZERO,
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let accumulator_gpu =
                        CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                    // Allocate the LweCiphertext to store the result of the PBS
                    let output_pbs_ct = LweCiphertext::new(
                        Scalar::ZERO,
                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut output_pbs_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&output_pbs_ct, &streams);

                    let h_indexes = [Scalar::ZERO];
                    let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            cuda_keyswitch_lwe_ciphertext(
                                gpu_keys.ksk.as_ref().unwrap(),
                                &input_ks_ct_gpu,
                                &mut output_ks_ct_gpu,
                                &cuda_indexes.d_input,
                                &cuda_indexes.d_output,
                                &streams,
                            );
                            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                                &output_ks_ct_gpu,
                                &mut output_pbs_ct_gpu,
                                &accumulator_gpu,
                                &cuda_indexes.d_lut,
                                &cuda_indexes.d_output,
                                &cuda_indexes.d_input,
                                gpu_keys.multi_bit_bsk.as_ref().unwrap(),
                                &streams,
                            );
                            black_box(&mut output_ks_ct_gpu);
                        })
                    });
                }
                BenchmarkType::Throughput => {
                    let gpu_keys_vec = cuda_local_keys_core(&cpu_keys, None);
                    let gpu_count = get_number_of_gpus() as usize;

                    bench_id = format!("{bench_name}::throughput::{name}");
                    println!("{bench_id}");
                    let blocks: usize = 1;
                    let elements = throughput_num_threads(blocks, 1);
                    let elements_per_stream = elements as usize / gpu_count;
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams_core();

                            let plaintext_list = PlaintextList::new(
                                Scalar::ZERO,
                                PlaintextCount(elements_per_stream),
                            );

                            let input_ks_cts = (0..gpu_count)
                                .map(|i| {
                                    let mut input_ks_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    encrypt_lwe_ciphertext_list(
                                        &output_lwe_secret_key,
                                        &mut input_ks_list,
                                        &plaintext_list,
                                        params.lwe_noise_distribution.unwrap(),
                                        &mut encryption_generator,
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &input_ks_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let output_ks_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_ks_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_ks_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let accumulators = (0..gpu_count)
                                .map(|i| {
                                    let accumulator = GlweCiphertext::new(
                                        Scalar::ZERO,
                                        params.glwe_dimension.unwrap().to_glwe_size(),
                                        params.polynomial_size.unwrap(),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaGlweCiphertextList::from_glwe_ciphertext(
                                        &accumulator,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            // Allocate the LweCiphertext to store the result of the PBS
                            let output_pbs_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_pbs_ct = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_pbs_ct,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let h_indexes = (0..(elements / gpu_count as u64))
                                .map(CastFrom::cast_from)
                                .collect::<Vec<_>>();
                            let cuda_indexes_vec = (0..gpu_count)
                                .map(|i| CudaIndexes::new(&h_indexes, &local_streams[i], 0))
                                .collect::<Vec<_>>();
                            local_streams.iter().for_each(|stream| stream.synchronize());

                            (
                                input_ks_cts,
                                output_ks_cts,
                                output_pbs_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(
                                input_ks_cts,
                                mut output_ks_cts,
                                mut output_pbs_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_ks_cts.par_iter())
                                    .zip(output_ks_cts.par_iter_mut())
                                    .zip(output_pbs_cts.par_iter_mut())
                                    .zip(accumulators.par_iter())
                                    .zip(local_streams.par_iter())
                                    .for_each(
                                        |(
                                            (
                                                (((i, input_ks_ct), output_ks_ct), output_pbs_ct),
                                                accumulator,
                                            ),
                                            local_stream,
                                        )| {
                                            cuda_keyswitch_lwe_ciphertext(
                                                gpu_keys_vec[i].ksk.as_ref().unwrap(),
                                                input_ks_ct,
                                                output_ks_ct,
                                                &cuda_indexes_vec[i].d_input,
                                                &cuda_indexes_vec[i].d_output,
                                                local_stream,
                                            );
                                            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                                                output_ks_ct,
                                                output_pbs_ct,
                                                accumulator,
                                                &cuda_indexes_vec[i].d_lut,
                                                &cuda_indexes_vec[i].d_output,
                                                &cuda_indexes_vec[i].d_input,
                                                gpu_keys_vec[i].multi_bit_bsk.as_ref().unwrap(),
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

            let bit_size = params.message_modulus.unwrap().ilog2();
            write_to_json(
                &bench_id,
                *params,
                name,
                "ks-pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    pub fn cuda_ks_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_ks_pbs(&mut criterion, &benchmark_parameters());
    }

    pub fn cuda_multi_bit_ks_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_multi_bit_ks_pbs(
            &mut criterion,
            &multi_bit_benchmark_parameters_with_grouping(),
        );
    }
}

#[cfg(feature = "gpu")]
use cuda::{cuda_ks_pbs_group, cuda_multi_bit_ks_pbs_group};

pub fn ks_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    ks_pbs(&mut criterion, &benchmark_parameters());
}

pub fn multi_bit_ks_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    multi_bit_ks_pbs(
        &mut criterion,
        &multi_bit_benchmark_parameters_with_grouping(),
        true,
    );
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical | ParamType::ClassicalDocumentation => cuda_ks_pbs_group(),
        ParamType::MultiBit | ParamType::MultiBitDocumentation => cuda_multi_bit_ks_pbs_group(),
    };
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical | ParamType::ClassicalDocumentation => ks_pbs_group(),
        ParamType::MultiBit | ParamType::MultiBitDocumentation => multi_bit_ks_pbs_group(),
    }
}

fn main() {
    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
