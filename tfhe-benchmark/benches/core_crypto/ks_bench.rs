#[cfg(feature = "boolean")]
use benchmark::params::benchmark_32bits_parameters;
use benchmark::params::{
    benchmark_compression_parameters, benchmark_parameters, multi_bit_benchmark_parameters,
};
use benchmark::utilities::{
    get_bench_type, get_param_type, throughput_num_threads, write_to_json, BenchmarkType,
    CryptoParametersRecord, OperatorType, ParamType,
};
use criterion::{black_box, Criterion, Throughput};
use itertools::Itertools;
use rayon::prelude::*;
use serde::Serialize;
use tfhe::core_crypto::prelude::*;

// TODO Refactor KS, PBS and KS-PBS benchmarks into a single generic function.
fn keyswitch<Scalar: UnsignedTorus + CastInto<usize> + Serialize>(
    criterion: &mut Criterion,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
) {
    let bench_name = "core_crypto::keyswitch";
    let mut bench_group = criterion.benchmark_group(bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in parameters.iter() {
        let lwe_dimension = params.lwe_dimension.unwrap();
        let glwe_dimension = params.glwe_dimension.unwrap();
        let polynomial_size = params.polynomial_size.unwrap();
        let ks_decomp_base_log = params.ks_base_log.unwrap();
        let ks_decomp_level_count = params.ks_level.unwrap();

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );
        let big_lwe_sk = glwe_sk.into_lwe_secret_key();
        let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_sk,
            &lwe_sk,
            ks_decomp_base_log,
            ks_decomp_level_count,
            params.lwe_noise_distribution.unwrap(),
            params.ciphertext_modulus.unwrap(),
            &mut encryption_generator,
        );

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let ct = allocate_and_encrypt_new_lwe_ciphertext(
                    &big_lwe_sk,
                    Plaintext(Scalar::ONE),
                    params.lwe_noise_distribution.unwrap(),
                    params.ciphertext_modulus.unwrap(),
                    &mut encryption_generator,
                );

                let mut output_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    lwe_sk.lwe_dimension().to_lwe_size(),
                    params.ciphertext_modulus.unwrap(),
                );

                bench_id = format!("{bench_name}::{name}");
                println!("{bench_id}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            keyswitch_lwe_ciphertext(&ksk_big_to_small, &ct, &mut output_ct);
                            black_box(&mut output_ct);
                        })
                    });
                }
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1); // FIXME This number of element do not staturate the target machine
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let input_cts = (0..elements)
                            .map(|_| {
                                allocate_and_encrypt_new_lwe_ciphertext(
                                    &big_lwe_sk,
                                    Plaintext(Scalar::ONE),
                                    params.lwe_noise_distribution.unwrap(),
                                    params.ciphertext_modulus.unwrap(),
                                    &mut encryption_generator,
                                )
                            })
                            .collect::<Vec<_>>();

                        let output_cts = (0..elements)
                            .map(|_| {
                                LweCiphertext::new(
                                    Scalar::ZERO,
                                    lwe_sk.lwe_dimension().to_lwe_size(),
                                    params.ciphertext_modulus.unwrap(),
                                )
                            })
                            .collect::<Vec<_>>();

                        (input_cts, output_cts)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(input_cts, mut output_cts)| {
                            input_cts
                                .par_iter()
                                .zip(output_cts.par_iter_mut())
                                .for_each(|(input_ct, output_ct)| {
                                    keyswitch_lwe_ciphertext(
                                        &ksk_big_to_small,
                                        input_ct,
                                        output_ct,
                                    );
                                })
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
            "ks",
            &OperatorType::Atomic,
            bit_size,
            vec![bit_size],
        );
    }
}

fn packing_keyswitch<Scalar, F>(
    criterion: &mut Criterion,
    bench_name: &str,
    parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ks_op: F,
) where
    Scalar: UnsignedTorus + CastInto<usize> + Serialize,
    F: Fn(
            &LwePackingKeyswitchKey<Vec<Scalar>>,
            &LweCiphertextList<Vec<Scalar>>,
            &mut GlweCiphertext<Vec<Scalar>>,
        ) + Sync
        + Send,
{
    let bench_name = format!("core_crypto::{bench_name}");
    let mut bench_group = criterion.benchmark_group(&bench_name);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    for (name, params) in parameters.iter() {
        let lwe_dimension = params.lwe_dimension.unwrap();
        let packing_glwe_dimension = params.packing_ks_glwe_dimension.unwrap();
        let packing_polynomial_size = params.packing_ks_polynomial_size.unwrap();
        let packing_ks_decomp_base_log = params.packing_ks_base_log.unwrap();
        let packing_ks_decomp_level_count = params.packing_ks_level.unwrap();
        let ciphertext_modulus = params.ciphertext_modulus.unwrap();
        let count = params.lwe_per_glwe.unwrap();

        let lwe_sk =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
            packing_glwe_dimension,
            packing_polynomial_size,
            &mut secret_generator,
        );

        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &lwe_sk,
            &glwe_sk,
            packing_ks_decomp_base_log,
            packing_ks_decomp_level_count,
            params.packing_ks_key_noise_distribution.unwrap(),
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let mut input_lwe_list = LweCiphertextList::new(
                    Scalar::ZERO,
                    lwe_sk.lwe_dimension().to_lwe_size(),
                    count,
                    ciphertext_modulus,
                );

                let plaintext_list = PlaintextList::new(
                    Scalar::ZERO,
                    PlaintextCount(input_lwe_list.lwe_ciphertext_count().0),
                );

                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut input_lwe_list,
                    &plaintext_list,
                    params.lwe_noise_distribution.unwrap(),
                    &mut encryption_generator,
                );

                let mut output_glwe = GlweCiphertext::new(
                    Scalar::ZERO,
                    glwe_sk.glwe_dimension().to_glwe_size(),
                    glwe_sk.polynomial_size(),
                    ciphertext_modulus,
                );

                bench_id = format!("{bench_name}::{name}");
                println!("{bench_id}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            ks_op(&pksk, &input_lwe_list, &mut output_glwe);
                            black_box(&mut output_glwe);
                        })
                    });
                }
            }
            BenchmarkType::Throughput => {
                bench_id = format!("{bench_name}::throughput::{name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let input_lwe_lists = (0..elements)
                            .map(|_| {
                                let mut input_lwe_list = LweCiphertextList::new(
                                    Scalar::ZERO,
                                    lwe_sk.lwe_dimension().to_lwe_size(),
                                    count,
                                    ciphertext_modulus,
                                );

                                let plaintext_list = PlaintextList::new(
                                    Scalar::ZERO,
                                    PlaintextCount(input_lwe_list.lwe_ciphertext_count().0),
                                );

                                encrypt_lwe_ciphertext_list(
                                    &lwe_sk,
                                    &mut input_lwe_list,
                                    &plaintext_list,
                                    params.lwe_noise_distribution.unwrap(),
                                    &mut encryption_generator,
                                );

                                input_lwe_list
                            })
                            .collect::<Vec<_>>();

                        let output_glwes = (0..elements)
                            .map(|_| {
                                GlweCiphertext::new(
                                    Scalar::ZERO,
                                    glwe_sk.glwe_dimension().to_glwe_size(),
                                    glwe_sk.polynomial_size(),
                                    ciphertext_modulus,
                                )
                            })
                            .collect::<Vec<_>>();

                        (input_lwe_lists, output_glwes)
                    };

                    b.iter_batched(
                        setup_encrypted_values,
                        |(input_lwe_lists, mut output_glwes)| {
                            input_lwe_lists
                                .par_iter()
                                .zip(output_glwes.par_iter_mut())
                                .for_each(|(input_lwe_list, output_glwe)| {
                                    ks_op(&pksk, input_lwe_list, output_glwe);
                                })
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
            "packing_ks",
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
        CudaLocalKeys, OperatorType,
    };
    use criterion::{black_box, Criterion, Throughput};
    use itertools::Itertools;
    use rayon::prelude::*;
    use serde::Serialize;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::vec::GpuIndex;
    use tfhe::core_crypto::gpu::{
        check_valid_cuda_malloc, cuda_keyswitch_lwe_ciphertext,
        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64, get_number_of_gpus,
        get_packing_keyswitch_list_64_size_on_gpu, CudaStreams,
    };

    use tfhe::core_crypto::prelude::*;

    fn cuda_keyswitch<Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64> + Serialize>(
        criterion: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::keyswitch";
        let mut bench_group = criterion.benchmark_group(bench_name);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        for (name, params) in parameters.iter() {
            let lwe_dimension = params.lwe_dimension.unwrap();
            let glwe_dimension = params.glwe_dimension.unwrap();
            let polynomial_size = params.polynomial_size.unwrap();
            let ks_decomp_base_log = params.ks_base_log.unwrap();
            let ks_decomp_level_count = params.ks_level.unwrap();

            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );
            let big_lwe_sk = glwe_sk.into_lwe_secret_key();
            let ksk_big_to_small = allocate_and_generate_new_lwe_keyswitch_key(
                &big_lwe_sk,
                &lwe_sk,
                ks_decomp_base_log,
                ks_decomp_level_count,
                params.lwe_noise_distribution.unwrap(),
                CiphertextModulus::new_native(),
                &mut encryption_generator,
            );

            let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new()
                .keyswitch_key(ksk_big_to_small)
                .build();

            let bench_id;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();
                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    let ct = allocate_and_encrypt_new_lwe_ciphertext(
                        &big_lwe_sk,
                        Plaintext(Scalar::ONE),
                        params.lwe_noise_distribution.unwrap(),
                        CiphertextModulus::new_native(),
                        &mut encryption_generator,
                    );
                    let mut ct_gpu = CudaLweCiphertextList::from_lwe_ciphertext(&ct, &streams);

                    let output_ct = LweCiphertext::new(
                        Scalar::ZERO,
                        lwe_sk.lwe_dimension().to_lwe_size(),
                        CiphertextModulus::new_native(),
                    );
                    let mut output_ct_gpu =
                        CudaLweCiphertextList::from_lwe_ciphertext(&output_ct, &streams);

                    let h_indexes = [Scalar::ZERO];
                    let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    {
                        bench_group.bench_function(&bench_id, |b| {
                            b.iter(|| {
                                cuda_keyswitch_lwe_ciphertext(
                                    gpu_keys.ksk.as_ref().unwrap(),
                                    &ct_gpu,
                                    &mut output_ct_gpu,
                                    &cuda_indexes.d_input,
                                    &cuda_indexes.d_output,
                                    &streams,
                                );
                                black_box(&mut ct_gpu);
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
                    bench_group.sample_size(50);
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
                                        big_lwe_sk.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    encrypt_lwe_ciphertext_list(
                                        &big_lwe_sk,
                                        &mut input_ct_list,
                                        &plaintext_list,
                                        params.lwe_noise_distribution.unwrap(),
                                        &mut encryption_generator,
                                    );
                                    let input_ks_list = LweCiphertextList::from_container(
                                        input_ct_list.into_container(),
                                        big_lwe_sk.lwe_dimension().to_lwe_size(),
                                        params.ciphertext_modulus.unwrap(),
                                    );
                                    CudaLweCiphertextList::from_lwe_ciphertext_list(
                                        &input_ks_list,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            let output_cts = (0..gpu_count)
                                .map(|i| {
                                    let output_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        lwe_sk.lwe_dimension().to_lwe_size(),
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

                            (input_cts, output_cts, cuda_indexes_vec, local_streams)
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(input_cts, mut output_cts, cuda_indexes_vec, local_streams)| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_cts.par_iter())
                                    .zip(output_cts.par_iter_mut())
                                    .zip(local_streams.par_iter())
                                    .for_each(|(((i, input_ct), output_ct), local_stream)| {
                                        cuda_keyswitch_lwe_ciphertext(
                                            gpu_keys_vec[i].ksk.as_ref().unwrap(),
                                            input_ct,
                                            output_ct,
                                            &cuda_indexes_vec[i].d_input,
                                            &cuda_indexes_vec[i].d_output,
                                            local_stream,
                                        );
                                    })
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
                "ks",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    fn cuda_packing_keyswitch<
        Scalar: UnsignedTorus + CastInto<usize> + CastFrom<u64> + Serialize,
    >(
        criterion: &mut Criterion,
        parameters: &[(String, CryptoParametersRecord<Scalar>)],
    ) {
        let bench_name = "core_crypto::cuda::packing_keyswitch";
        let mut bench_group = criterion.benchmark_group(bench_name);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        for (name, params) in parameters.iter() {
            let lwe_dimension = params.lwe_dimension.unwrap();
            let glwe_dimension = params.glwe_dimension.unwrap();
            let polynomial_size = params.polynomial_size.unwrap();
            let ks_decomp_base_log = params.ks_base_log.unwrap();
            let ks_decomp_level_count = params.ks_level.unwrap();
            let glwe_noise_distribution = params.glwe_noise_distribution.unwrap();
            let ciphertext_modulus = params.ciphertext_modulus.unwrap();

            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );

            let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
                &lwe_sk,
                &glwe_sk,
                ks_decomp_base_log,
                ks_decomp_level_count,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new().packing_keyswitch_key(pksk).build();

            let bench_id;
            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();

                    let mem_size = get_packing_keyswitch_list_64_size_on_gpu(
                        &streams,
                        lwe_sk.lwe_dimension(),
                        glwe_sk.glwe_dimension(),
                        glwe_sk.polynomial_size(),
                        LweCiphertextCount(glwe_sk.polynomial_size().0),
                    );

                    let skip_bench = !check_valid_cuda_malloc(mem_size, GpuIndex::new(0));

                    if skip_bench {
                        continue;
                    }

                    let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                    let mut input_ct_list = LweCiphertextList::new(
                        Scalar::ZERO,
                        lwe_sk.lwe_dimension().to_lwe_size(),
                        LweCiphertextCount(glwe_sk.polynomial_size().0),
                        ciphertext_modulus,
                    );

                    let plaintext_list = PlaintextList::new(
                        Scalar::ZERO,
                        PlaintextCount(input_ct_list.lwe_ciphertext_count().0),
                    );

                    encrypt_lwe_ciphertext_list(
                        &lwe_sk,
                        &mut input_ct_list,
                        &plaintext_list,
                        params.lwe_noise_distribution.unwrap(),
                        &mut encryption_generator,
                    );

                    let mut d_input_lwe_list =
                        CudaLweCiphertextList::from_lwe_ciphertext_list(&input_ct_list, &streams);

                    let mut d_output_glwe = CudaGlweCiphertextList::new(
                        glwe_sk.glwe_dimension(),
                        glwe_sk.polynomial_size(),
                        GlweCiphertextCount(1),
                        ciphertext_modulus,
                        &streams,
                    );

                    streams.synchronize();

                    bench_id = format!("{bench_name}::{name}");
                    println!("{bench_id}");
                    {
                        bench_group.bench_function(&bench_id, |b| {
                            b.iter(|| {
                                cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64(
                                    gpu_keys.pksk.as_ref().unwrap(),
                                    &d_input_lwe_list,
                                    &mut d_output_glwe,
                                    &streams,
                                );
                                black_box(&mut d_input_lwe_list);
                            })
                        });
                    }
                }
                BenchmarkType::Throughput => {
                    let gpu_keys_vec = cuda_local_keys_core(&cpu_keys, None);
                    let gpu_count = get_number_of_gpus() as usize;

                    bench_id = format!("{bench_name}::throughput::{name}");
                    println!("{bench_id}");

                    let mem_size = get_packing_keyswitch_list_64_size_on_gpu(
                        &CudaStreams::new_single_gpu(GpuIndex::new(0)),
                        lwe_sk.lwe_dimension(),
                        glwe_sk.glwe_dimension(),
                        glwe_sk.polynomial_size(),
                        LweCiphertextCount(glwe_sk.polynomial_size().0),
                    );

                    let mut skip_test = false;
                    for gpu_index in 0..gpu_count {
                        if !check_valid_cuda_malloc(mem_size, GpuIndex::new(gpu_index as u32)) {
                            skip_test = true;
                        }
                    }

                    if skip_test {
                        continue;
                    }

                    let blocks: usize = 1;
                    let elements = throughput_num_threads(blocks, 1);
                    let elements_per_stream =
                        std::cmp::min(elements as usize / gpu_count, glwe_sk.polynomial_size().0);
                    bench_group.throughput(Throughput::Elements(elements));
                    bench_group.sample_size(50);
                    bench_group.bench_function(&bench_id, |b| {
                        let setup_encrypted_values = || {
                            let local_streams = cuda_local_streams_core();

                            let plaintext_list = PlaintextList::new(
                                Scalar::ZERO,
                                PlaintextCount(elements_per_stream),
                            );

                            let input_lwe_lists = (0..gpu_count)
                                .map(|i| {
                                    let mut input_ct_list = LweCiphertextList::new(
                                        Scalar::ZERO,
                                        lwe_sk.lwe_dimension().to_lwe_size(),
                                        LweCiphertextCount(elements_per_stream),
                                        ciphertext_modulus,
                                    );
                                    encrypt_lwe_ciphertext_list(
                                        &lwe_sk,
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

                            let output_glwe_list = (0..gpu_count)
                                .map(|i| {
                                    CudaGlweCiphertextList::new(
                                        glwe_sk.glwe_dimension(),
                                        glwe_sk.polynomial_size(),
                                        GlweCiphertextCount(1),
                                        ciphertext_modulus,
                                        &local_streams[i],
                                    )
                                })
                                .collect::<Vec<_>>();

                            local_streams.iter().for_each(|stream| stream.synchronize());

                            (input_lwe_lists, output_glwe_list, local_streams)
                        };

                        b.iter_batched(
                            setup_encrypted_values,
                            |(input_lwe_lists, mut output_glwe_lists, local_streams)| {
                                (0..gpu_count)
                                    .into_par_iter()
                                    .zip(input_lwe_lists.par_iter())
                                    .zip(output_glwe_lists.par_iter_mut())
                                    .zip(local_streams.par_iter())
                                    .for_each(
                                        |(
                                            ((i, input_lwe_list), output_glwe_list),
                                            local_stream,
                                        )| {
                                            cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64(
                                                gpu_keys_vec[i].pksk.as_ref().unwrap(),
                                                input_lwe_list,
                                                output_glwe_list,
                                                local_stream,
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
                "packing_ks",
                &OperatorType::Atomic,
                bit_size,
                vec![bit_size],
            );
        }
    }

    pub fn cuda_ks_group() {
        let mut criterion: Criterion<_> = (Criterion::default().sample_size(15))
            .measurement_time(std::time::Duration::from_secs(60))
            .configure_from_args();
        cuda_keyswitch(&mut criterion, &benchmark_parameters());
        cuda_packing_keyswitch(&mut criterion, &benchmark_parameters());
    }

    pub fn cuda_ks_group_documentation() {
        let mut criterion: Criterion<_> = (Criterion::default().sample_size(15))
            .measurement_time(std::time::Duration::from_secs(60))
            .configure_from_args();
        cuda_keyswitch(&mut criterion, &benchmark_parameters());
    }

    pub fn cuda_multi_bit_ks_group() {
        let mut criterion: Criterion<_> =
            (Criterion::default().sample_size(2000)).configure_from_args();
        let multi_bit_parameters = multi_bit_benchmark_parameters()
            .into_iter()
            .map(|(string, params, _)| (string, params))
            .collect_vec();
        cuda_keyswitch(&mut criterion, &multi_bit_parameters);
        cuda_packing_keyswitch(&mut criterion, &multi_bit_parameters);
    }

    pub fn cuda_multi_bit_ks_group_documentation() {
        let mut criterion: Criterion<_> =
            (Criterion::default().sample_size(2000)).configure_from_args();
        let multi_bit_parameters = multi_bit_benchmark_parameters()
            .into_iter()
            .map(|(string, params, _)| (string, params))
            .collect_vec();
        cuda_keyswitch(&mut criterion, &multi_bit_parameters);
    }
}

#[cfg(feature = "gpu")]
use cuda::{
    cuda_ks_group, cuda_ks_group_documentation, cuda_multi_bit_ks_group,
    cuda_multi_bit_ks_group_documentation,
};

pub fn ks_group() {
    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60)))
    .configure_from_args();
    keyswitch(&mut criterion, &benchmark_parameters());
    #[cfg(feature = "boolean")]
    keyswitch(&mut criterion, &benchmark_32bits_parameters());
}

pub fn multi_bit_ks_group() {
    let multi_bit_parameters = multi_bit_benchmark_parameters()
        .into_iter()
        .map(|(string, params, _)| (string, params))
        .collect_vec();

    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60)))
    .configure_from_args();
    keyswitch(&mut criterion, &multi_bit_parameters);
}

pub fn packing_ks_group() {
    let mut criterion: Criterion<_> = (Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30)))
    .configure_from_args();
    packing_keyswitch(
        &mut criterion,
        "packing_keyswitch",
        &benchmark_compression_parameters(),
        keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
    );
    packing_keyswitch(
        &mut criterion,
        "par_packing_keyswitch",
        &benchmark_compression_parameters(),
        par_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext,
    );
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical => cuda_ks_group(),
        ParamType::ClassicalDocumentation => cuda_ks_group_documentation(),
        ParamType::MultiBit => cuda_multi_bit_ks_group(),
        ParamType::MultiBitDocumentation => cuda_multi_bit_ks_group_documentation(),
    };
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    match get_param_type() {
        ParamType::Classical => {
            ks_group();
            packing_ks_group()
        }
        ParamType::ClassicalDocumentation => ks_group(),
        ParamType::MultiBit | ParamType::MultiBitDocumentation => multi_bit_ks_group(),
    }
}

fn main() {
    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
