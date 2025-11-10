use benchmark::params::{
    benchmark_32bits_parameters, benchmark_parameters,
    multi_bit_benchmark_parameters_with_grouping, multi_bit_num_threads,
};
use benchmark::utilities::{
    get_bench_type, get_param_type, throughput_num_threads, write_to_json, BenchmarkType,
    CryptoParametersRecord, OperatorType, ParamType,
};
use criterion::{black_box, Criterion, Throughput};
use rayon::prelude::*;
use serde::Serialize;
use tfhe::core_crypto::commons::math::ntt::ntt64::Ntt64;
use tfhe::core_crypto::prelude::*;

// TODO Refactor KS, PBS and KS-PBS benchmarks into a single generic function.
fn mem_optimized_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::pbs_mem_optimized";
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
                let lwe_ciphertext_in: LweCiphertextOwned<Scalar> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        Plaintext(Scalar::ZERO),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );

                let accumulator = GlweCiphertext::new(
                    Scalar::ZERO,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut out_pbs_ct = LweCiphertext::new(
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

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            &lwe_ciphertext_in,
                            &mut out_pbs_ct,
                            &accumulator.as_view(),
                            &fourier_bsk,
                            fft,
                            buffers.stack(),
                        );
                        black_box(&mut out_pbs_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let fft = Fft::new(fourier_bsk.polynomial_size());

                    let setup_encrypted_values = || {
                        let input_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &input_lwe_secret_key,
                                    Plaintext(Scalar::ZERO),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator,
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
                        let output_cts = (0..elements)
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
                            input_cts,
                            output_cts,
                            accumulators,
                            buffers,
                        )
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(
                             input_cts,
                             mut output_cts,
                             accumulators,
                             mut buffers,
                         )| {
                            input_cts
                                .par_iter()
                                .zip(output_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .zip(buffers.par_iter_mut())
                                .for_each(
                                    |(
                                         (
                                             (input_ct,  output_ct),
                                             accumulator),
                                         buffer,
                                     )| {
                                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                            input_ct,
                                            output_ct,
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
        };

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &bench_id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn mem_optimized_batched_pbs<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::batched_pbs_mem_optimized";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(10));

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

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            params.lwe_dimension.unwrap(),
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
        );

        let count = 10; // FIXME Is it a representative value (big enough?)

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Allocate a new LweCiphertext and encrypt our plaintext
                let mut lwe_ciphertext_in = LweCiphertextListOwned::<Scalar>::new(
                    Scalar::ZERO,
                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    LweCiphertextCount(count),
                    params.ciphertext_modulus.unwrap(),
                );

                encrypt_lwe_ciphertext_list(
                    &input_lwe_secret_key,
                    &mut lwe_ciphertext_in,
                    &PlaintextList::from_container(vec![Scalar::ZERO; count]),
                    params.lwe_noise_distribution.unwrap(),
                    &mut encryption_generator,
                );

                let accumulator = GlweCiphertextList::new(
                    Scalar::ZERO,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    GlweCiphertextCount(count),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut out_pbs_ct = LweCiphertextList::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    LweCiphertextCount(count),
                    params.ciphertext_modulus.unwrap(),
                );

                let mut buffers = ComputationBuffers::new();

                let fft = Fft::new(fourier_bsk.polynomial_size());
                let fft = fft.as_view();

                buffers.resize(
            batch_programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<Scalar>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                CiphertextCount(count),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

                bench_id = format!("{bench_name}::{name}");
                println!("{bench_id}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            &lwe_ciphertext_in,
                            &mut out_pbs_ct,
                            &accumulator,
                            &fourier_bsk,
                            fft,
                            buffers.stack(),
                        );
                        black_box(&mut out_pbs_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let fft = Fft::new(fourier_bsk.polynomial_size());

                    let setup_encrypted_values = || {
                        let input_cts = (0..elements)
                            .map(|_| {
                                let mut lwe_ciphertext_in = LweCiphertextListOwned::<Scalar>::new(
                                    Scalar::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(count),
                                    params.ciphertext_modulus.unwrap(),
                                );

                                encrypt_lwe_ciphertext_list(
                                    &input_lwe_secret_key,
                                    &mut lwe_ciphertext_in,
                                    &PlaintextList::from_container(vec![Scalar::ZERO; count]),
                                    params.lwe_noise_distribution.unwrap(),
                                    &mut encryption_generator,
                                );

                                lwe_ciphertext_in
                            })
                            .collect::<Vec<_>>();

                        let accumulators = (0..elements)
                            .map(|_| {
                                GlweCiphertextList::new(
                                    Scalar::ZERO,
                                    params.glwe_dimension.unwrap().to_glwe_size(),
                                    params.polynomial_size.unwrap(),
                                    GlweCiphertextCount(count),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // Allocate the LweCiphertext to store the result of the PBS
                        let output_cts = (0..elements)
                            .map(|_| {
                                LweCiphertextList::new(
                                    Scalar::ZERO,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(count),
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
                            input_cts,
                            output_cts,
                            accumulators,
                            buffers,
                        )
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(
                             input_ct_lists,
                             mut output_ct_lists,
                             accumulators,
                             mut buffers,
                         )| {
                            input_ct_lists
                                .par_iter()
                                .zip(output_ct_lists.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .zip(buffers.par_iter_mut())
                                .for_each(
                                    |(
                                         (
                                             (input_ct_list, output_ct_list),
                                             accumulator),
                                         buffer,
                                     )| {
                                        batch_programmable_bootstrap_lwe_ciphertext_mem_optimized(
                                            input_ct_list,
                                            output_ct_list,
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
        };

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &bench_id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn multi_bit_pbs<
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize> + Default + Sync + Serialize,
>(
    c: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    deterministic_pbs: bool,
) {
    let bench_name = if deterministic_pbs {
        "core_crypto::multi_bit_deterministic_pbs"
    } else {
        "core_crypto::multi_bit_pbs"
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
                let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                    &input_lwe_secret_key,
                    Plaintext(Scalar::ZERO),
                    params.lwe_noise_distribution.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                    &mut encryption_generator,
                );

                let accumulator = GlweCiphertext::new(
                    Scalar::ZERO,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                bench_id = format!("{bench_name}::{name}::parallelized");
                println!("{bench_id}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &lwe_ciphertext_in,
                            &mut out_pbs_ct,
                            &accumulator.as_view(),
                            &multi_bit_bsk,
                            ThreadCount(thread_count),
                            deterministic_pbs,
                        );
                        black_box(&mut out_pbs_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let input_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &input_lwe_secret_key,
                                    Plaintext(Scalar::ZERO),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator,
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
                        let output_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        (input_cts, output_cts, accumulators)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(input_ks_cts, mut output_pbs_cts, accumulators)| {
                            input_ks_cts
                                .par_iter()
                                .zip(output_pbs_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .for_each(|((input_ks_ct, output_pbs_ct), accumulator)| {
                                    multi_bit_programmable_bootstrap_lwe_ciphertext(
                                        input_ks_ct,
                                        output_pbs_ct,
                                        &accumulator.as_view(),
                                        &multi_bit_bsk,
                                        ThreadCount(thread_count),
                                        deterministic_pbs,
                                    );
                                })
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
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn mem_optimized_pbs_ntt(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs_ntt";
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

    let custom_ciphertext_modulus =
        tfhe::core_crypto::prelude::CiphertextModulus::new((1 << 64) - (1 << 32) + 1);

    for (name, params) in benchmark_parameters().iter_mut() {
        if let (Some(lwe_noise), Some(glwe_noise)) = (
            params.lwe_noise_distribution,
            params.glwe_noise_distribution,
        ) {
            match (lwe_noise, glwe_noise) {
                (DynamicDistribution::Gaussian(_), DynamicDistribution::Gaussian(_)) => (),
                _ => {
                    println!(
                        "Skip {name} parameters set: custom modulus generation is not supported"
                    );
                    continue;
                }
            }
        };

        let name = format!("{name}_PLACEHOLDER_NTT");

        params.ciphertext_modulus = Some(custom_ciphertext_modulus);

        // Create the LweSecretKey
        let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            params.lwe_dimension.unwrap(),
            &mut secret_generator,
        );
        let output_glwe_secret_key: GlweSecretKeyOwned<u64> =
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension.unwrap(),
                params.polynomial_size.unwrap(),
                &mut secret_generator,
            );
        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let mut bsk = LweBootstrapKey::new(
            0u64,
            params.glwe_dimension.unwrap().to_glwe_size(),
            params.polynomial_size.unwrap(),
            params.pbs_base_log.unwrap(),
            params.pbs_level.unwrap(),
            params.lwe_dimension.unwrap(),
            params.ciphertext_modulus.unwrap(),
        );

        par_generate_lwe_bootstrap_key(
            &input_lwe_secret_key,
            &output_glwe_secret_key,
            &mut bsk,
            params.glwe_noise_distribution.unwrap(),
            &mut encryption_generator,
        );

        let mut nbsk = NttLweBootstrapKeyOwned::new(
            0u64,
            bsk.input_lwe_dimension(),
            bsk.glwe_size(),
            bsk.polynomial_size(),
            bsk.decomposition_base_log(),
            bsk.decomposition_level_count(),
            bsk.ciphertext_modulus(),
        );

        par_convert_standard_lwe_bootstrap_key_to_ntt64(
            &bsk,
            &mut nbsk,
            NttLweBootstrapKeyOption::Normalize,
        );

        drop(bsk);

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Allocate a new LweCiphertext and encrypt our plaintext
                let lwe_ciphertext_in: LweCiphertextOwned<u64> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        Plaintext(0u64),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );

                let accumulator = GlweCiphertext::new(
                    0u64,
                    params.glwe_dimension.unwrap().to_glwe_size(),
                    params.polynomial_size.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                );

                // Allocate the LweCiphertext to store the result of the PBS
                let mut out_pbs_ct = LweCiphertext::new(
                    0u64,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                let ntt = Ntt64::new(params.ciphertext_modulus.unwrap(), nbsk.polynomial_size());
                let ntt = ntt.as_view();

                let mut buffers = ComputationBuffers::new();

                let stack_size =
                    programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        ntt,
                    )
                    .unwrap()
                    .try_unaligned_bytes_required()
                    .unwrap();

                buffers.resize(stack_size);

                bench_id = format!("{bench_name}::{name}");
                println!("{bench_id}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
                            &lwe_ciphertext_in,
                            &mut out_pbs_ct,
                            &accumulator,
                            &nbsk,
                            ntt,
                            buffers.stack(),
                        );
                        black_box(&mut out_pbs_ct);
                    })
                });
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let ntt = Ntt64::new(params.ciphertext_modulus.unwrap(), nbsk.polynomial_size());

                    let setup_encrypted_values = || {
                        let input_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &input_lwe_secret_key,
                                    Plaintext(0u64),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator)
                            })
                            .collect::<Vec<LweCiphertextOwned<u64>>>();

                        let accumulators = (0..elements)
                            .map(|_| {
                                GlweCiphertext::new(
                                    0u64,
                                    params.glwe_dimension.unwrap().to_glwe_size(),
                                    params.polynomial_size.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // Allocate the LweCiphertext to store the result of the PBS
                        let output_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    0u64,
                                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        let buffers = (0..elements)
                            .map(|_| {
                                let mut buffer = ComputationBuffers::new();

                                let stack_size = programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
                                    params.glwe_dimension.unwrap().to_glwe_size(),
                                    params.polynomial_size.unwrap(),
                                    ntt.as_view(),
                                )
                                    .unwrap()
                                    .try_unaligned_bytes_required()
                                    .unwrap();

                                buffer.resize(stack_size);

                                buffer
                            })
                            .collect::<Vec<_>>();

                        (
                            input_cts,
                            output_cts,
                            accumulators,
                            buffers,
                        )
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(
                             input_cts,
                             mut output_cts,
                             accumulators,
                             mut buffers,
                         )| {
                            input_cts
                                .par_iter()
                                .zip(output_cts.par_iter_mut())
                                .zip(accumulators.par_iter())
                                .zip(buffers.par_iter_mut())
                                .for_each(
                                    |(
                                         (
                                             (input_ct,  output_ct),
                                             accumulator),
                                         buffer,
                                     )| {
                                        programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized(
                                            input_ct,
                                            output_ct,
                                            accumulator,
                                            &nbsk,
                                            ntt.as_view(),
                                            buffer.stack(),
                                        );
                                    },
                                )
                        },
                        criterion::BatchSize::SmallInput,
                    )
                });
            }
        };

        let bit_size = (params.message_modulus.unwrap_or(2) as u32).ilog2();
        write_to_json(
            &bench_id,
            *params,
            name,
            "pbs",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

#[cfg(feature = "gpu")]
mod cuda {
    use benchmark::params::{benchmark_parameters, multi_bit_benchmark_parameters};
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
        cuda_multi_bit_programmable_bootstrap_lwe_ciphertext,
        cuda_programmable_bootstrap_lwe_ciphertext, get_number_of_gpus, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;

    fn cuda_pbs<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64> + Serialize>(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::pbs";
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

            let bsk = LweBootstrapKey::new(
                Scalar::ZERO,
                params.glwe_dimension.unwrap().to_glwe_size(),
                params.polynomial_size.unwrap(),
                params.pbs_base_log.unwrap(),
                params.pbs_level.unwrap(),
                params.lwe_dimension.unwrap(),
                params.ciphertext_modulus.unwrap(),
            );

            let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new().bootstrap_key(bsk).build();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    // Allocate a new LweCiphertext and encrypt our plaintext
                    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        Plaintext(Scalar::ZERO),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );
                    let lwe_ciphertext_in_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &streams);

                    let accumulator = GlweCiphertext::new(
                        Scalar::ZERO,
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let accumulator_gpu =
                        CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                    // Allocate the LweCiphertext to store the result of the PBS
                    let out_pbs_ct = LweCiphertext::new(
                        Scalar::ZERO,
                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut out_pbs_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &streams);

                    let h_indexes = [Scalar::ZERO];
                    let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    {
                        bench_group.bench_function(&bench_id, |b| {
                            b.iter(|| {
                                cuda_programmable_bootstrap_lwe_ciphertext(
                                    &lwe_ciphertext_in_gpu,
                                    &mut out_pbs_ct_gpu,
                                    &accumulator_gpu,
                                    &cuda_indexes.d_lut,
                                    &cuda_indexes.d_output,
                                    &cuda_indexes.d_input,
                                    gpu_keys.bsk.as_ref().unwrap(),
                                    &streams,
                                );
                                black_box(&mut out_pbs_ct_gpu);
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

                            let input_cts = (0..gpu_count)
                                .map(|i| {
                                    let mut input_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );

                                    encrypt_lwe_ciphertext_list(
                                        &input_lwe_secret_key,
                                        &mut input_ct_list,
                                        &plaintext_list,
                                        params.lwe_noise_distribution.unwrap(),
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
                            let output_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_ct_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let h_indexes = (0..elements_per_stream as u64)
                                .map(CastFrom::cast_from)
                                .collect::<Vec<_>>();
                            let cuda_indexes_vec = (0..gpu_count)
                                .map(|i| CudaIndexes::new(&h_indexes, &local_streams[i], 0))
                                .collect::<Vec<_>>();
                            local_streams.iter().for_each(|stream| stream.synchronize());

                            (
                                input_cts,
                                output_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(
                                input_cts,
                                mut output_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_cts.par_iter())
                                    .zip(output_cts.par_iter_mut())
                                    .zip(accumulators.par_iter())
                                    .zip(local_streams.par_iter())
                                    .for_each(
                                        |(
                                            (((i, input_ct), output_ct), accumulator),
                                            local_stream,
                                        )| {
                                            cuda_programmable_bootstrap_lwe_ciphertext(
                                                input_ct,
                                                output_ct,
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
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_multi_bit_pbs<
        Scalar: UnsignedTorus
            + CastInto<usize>
            + CastFrom<usize>
            + CastFrom<u64>
            + Default
            + Serialize
            + Sync,
    >(
        c: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>, LweBskGroupingFactor)],
    ) {
        let bench_name = "core_crypto::cuda::multi_bit_pbs";
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
                .multi_bit_bootstrap_key(multi_bit_bsk)
                .build();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    // Allocate a new LweCiphertext and encrypt our plaintext
                    let lwe_ciphertext_in = allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        Plaintext(Scalar::ZERO),
                        params.lwe_noise_distribution.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                        &mut encryption_generator,
                    );
                    let lwe_ciphertext_in_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &streams);

                    let accumulator = GlweCiphertext::new(
                        Scalar::ZERO,
                        params.glwe_dimension.unwrap().to_glwe_size(),
                        params.polynomial_size.unwrap(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let accumulator_gpu =
                        CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                    // Allocate the LweCiphertext to store the result of the PBS
                    let out_pbs_ct = LweCiphertext::new(
                        Scalar::ZERO,
                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                        params.ciphertext_modulus.unwrap(),
                    );
                    let mut out_pbs_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &streams);

                    let h_indexes = [Scalar::ZERO];
                    let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                                &lwe_ciphertext_in_gpu,
                                &mut out_pbs_ct_gpu,
                                &accumulator_gpu,
                                &cuda_indexes.d_lut,
                                &cuda_indexes.d_output,
                                &cuda_indexes.d_input,
                                gpu_keys.multi_bit_bsk.as_ref().unwrap(),
                                &streams,
                            );
                            black_box(&mut out_pbs_ct_gpu);
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

                            let input_cts = (0..gpu_count)
                                .map(|i| {
                                    let mut input_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );

                                    encrypt_lwe_ciphertext_list(
                                        &input_lwe_secret_key,
                                        &mut input_ct_list,
                                        &plaintext_list,
                                        params.lwe_noise_distribution.unwrap(),
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
                            let output_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &output_ct_list,
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
                                input_cts,
                                output_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(
                                input_cts,
                                mut output_cts,
                                accumulators,
                                cuda_indexes_vec,
                                local_streams,
                            )| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_cts.par_iter())
                                    .zip(output_cts.par_iter_mut())
                                    .zip(accumulators.par_iter())
                                    .zip(local_streams.par_iter())
                                    .for_each(
                                        |(
                                            (((i, input_ct), output_ct), accumulator),
                                            local_stream,
                                        )| {
                                            cuda_multi_bit_programmable_bootstrap_lwe_ciphertext(
                                                input_ct,
                                                output_ct,
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
                "pbs",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    pub fn cuda_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_pbs(&mut criterion, &benchmark_parameters());
    }

    pub fn cuda_multi_bit_pbs_group() {
        let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
        cuda_multi_bit_pbs(&mut criterion, &multi_bit_benchmark_parameters());
    }
}

#[cfg(feature = "gpu")]
use cuda::{cuda_multi_bit_pbs_group, cuda_pbs_group};

pub fn pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    mem_optimized_pbs(&mut criterion, &benchmark_parameters());
    mem_optimized_pbs(&mut criterion, &benchmark_32bits_parameters());
    mem_optimized_pbs_ntt(&mut criterion);
    mem_optimized_batched_pbs(&mut criterion, &benchmark_parameters());
}

pub fn pbs_group_documentation() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    mem_optimized_pbs(&mut criterion, &benchmark_parameters());
}

pub fn multi_bit_pbs_group() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    multi_bit_pbs(
        &mut criterion,
        &multi_bit_benchmark_parameters_with_grouping(),
        false,
    );
    multi_bit_pbs(
        &mut criterion,
        &multi_bit_benchmark_parameters_with_grouping(),
        true,
    );
}

pub fn multi_bit_pbs_group_documentation() {
    let mut criterion: Criterion<_> = (Criterion::default()).configure_from_args();
    multi_bit_pbs(
        &mut criterion,
        &multi_bit_benchmark_parameters_with_grouping(),
        true,
    );
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical => cuda_pbs_group(),
        ParamType::ClassicalDocumentation => cuda_pbs_group(),
        ParamType::MultiBit => cuda_multi_bit_pbs_group(),
        ParamType::MultiBitDocumentation => cuda_multi_bit_pbs_group(),
    };
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical => pbs_group(),
        ParamType::ClassicalDocumentation => pbs_group_documentation(),
        ParamType::MultiBit => multi_bit_pbs_group(),
        ParamType::MultiBitDocumentation => multi_bit_pbs_group_documentation(),
    }
}

fn main() {
    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
