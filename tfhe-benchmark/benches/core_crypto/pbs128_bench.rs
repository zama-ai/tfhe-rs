use benchmark::params_aliases::{
    BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use benchmark::utilities::{write_to_json, CryptoParametersRecord, OperatorType};
use criterion::{black_box, Criterion};
use dyn_stack::PodStack;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::bootstrap_scratch;
use tfhe::core_crypto::prelude::*;
use tfhe::keycache::NamedParam;

fn pbs_128(c: &mut Criterion) {
    let bench_name = "core_crypto::pbs128";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30));

    type InputScalar = u64;
    type OutputScalar = u128;

    let noise_params = BENCH_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let base_params = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let lwe_dimension = base_params.lwe_dimension; // From PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    let glwe_dimension = noise_params.glwe_dimension();
    let polynomial_size = noise_params.polynomial_size();
    let lwe_noise_distribution = base_params.lwe_noise_distribution;
    let glwe_noise_distribution = noise_params.glwe_noise_distribution();
    let pbs_base_log = noise_params.decomp_base_log();
    let pbs_level = noise_params.decomp_level_count();
    let input_ciphertext_modulus = base_params.ciphertext_modulus;
    let output_ciphertext_modulus = noise_params.ciphertext_modulus();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let input_lwe_secret_key =
        LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    let output_glwe_secret_key = GlweSecretKey::<Vec<OutputScalar>>::generate_new_binary(
        glwe_dimension,
        polynomial_size,
        &mut secret_generator,
    );

    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    let mut bsk = LweBootstrapKey::new(
        OutputScalar::ZERO,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        pbs_base_log,
        pbs_level,
        lwe_dimension,
        output_ciphertext_modulus,
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

    let message_modulus: InputScalar = 1 << 4;

    let input_message: InputScalar = 3;

    let delta: InputScalar = (1 << (InputScalar::BITS - 1)) / message_modulus;

    let plaintext = Plaintext(input_message * delta);

    let lwe_ciphertext_in: LweCiphertextOwned<InputScalar> =
        allocate_and_encrypt_new_lwe_ciphertext(
            &input_lwe_secret_key,
            plaintext,
            lwe_noise_distribution,
            input_ciphertext_modulus,
            &mut encryption_generator,
        );

    let accumulator: GlweCiphertextOwned<OutputScalar> = GlweCiphertextOwned::new(
        OutputScalar::ONE,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
        output_ciphertext_modulus,
    );

    let mut out_pbs_ct: LweCiphertext<Vec<OutputScalar>> = LweCiphertext::new(
        OutputScalar::ZERO,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        output_ciphertext_modulus,
    );

    let fft = Fft128::new(polynomial_size);
    let fft = fft.as_view();

    let mut buffers = vec![
        0u8;
        bootstrap_scratch::<OutputScalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft
        )
        .unwrap()
        .unaligned_bytes_required()
    ];

    let id = format!("{bench_name}::{}", noise_params.name());
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

    // TODO Add throughput benchmark case

    let params_record = CryptoParametersRecord {
        lwe_dimension: Some(lwe_dimension),
        glwe_dimension: Some(glwe_dimension),
        polynomial_size: Some(polynomial_size),
        lwe_noise_distribution: Some(lwe_noise_distribution),
        glwe_noise_distribution: Some(base_params.glwe_noise_distribution),
        pbs_base_log: Some(pbs_base_log),
        pbs_level: Some(pbs_level),
        ciphertext_modulus: Some(input_ciphertext_modulus),
        ..Default::default()
    };

    let bit_size = (message_modulus as u32).ilog2();
    write_to_json(
        &id,
        params_record,
        noise_params.name(),
        "pbs",
        &OperatorType::Atomic,
        bit_size,
        vec![bit_size],
    );
}

#[cfg(feature = "gpu")]
mod cuda {
    use benchmark::utilities::{
        cuda_local_keys_core, cuda_local_streams_core, get_bench_type, throughput_num_threads,
        write_to_json, BenchmarkType, CpuKeys, CpuKeysBuilder, CryptoParametersRecord, CudaIndexes,
        CudaLocalKeys, OperatorType,
    };
    use criterion::{black_box, Criterion, Throughput};
    use rayon::prelude::*;
    use tfhe::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaModulusSwitchNoiseReductionConfiguration;
    use tfhe::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
    use tfhe::core_crypto::gpu::{
        cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext,
        cuda_programmable_bootstrap_128_lwe_ciphertext, get_number_of_gpus, CudaStreams,
    };
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::parameters::{
        ModulusSwitchType, NoiseSquashingParameters,
        NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };

    fn cuda_pbs_128(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::pbs128";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        type Scalar = u128;
        let input_params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let squash_params = NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let NoiseSquashingParameters::Classic(squash_params) = squash_params else {
            panic!("Multi bit noise squashing PBS currently not supported on GPU");
        };

        let lwe_noise_distribution_u64 = DynamicDistribution::new_t_uniform(46);
        let ct_modulus_u64: CiphertextModulus<u64> = CiphertextModulus::new_native();

        let params_name = "PARAMS_SWITCH_SQUASH";

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let input_lwe_secret_key =
            LweSecretKey::generate_new_binary(input_params.lwe_dimension, &mut secret_generator);

        let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            squash_params.glwe_dimension,
            squash_params.polynomial_size,
            &mut secret_generator,
        );

        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let bsk = LweBootstrapKey::new(
            Scalar::ZERO,
            squash_params.glwe_dimension.to_glwe_size(),
            squash_params.polynomial_size,
            squash_params.decomp_base_log,
            squash_params.decomp_level_count,
            LweDimension(input_params.lwe_dimension.0),
            squash_params.ciphertext_modulus,
        );

        let streams = CudaStreams::new_multi_gpu();

        let modulus_switch_noise_reduction_configuration =
            match squash_params.modulus_switch_noise_reduction_params {
                ModulusSwitchType::Standard => None,
                ModulusSwitchType::DriftTechniqueNoiseReduction(
                    _modulus_switch_noise_reduction_params,
                ) => {
                    panic!("Drift noise reduction is not supported on GPU")
                }
                ModulusSwitchType::CenteredMeanNoiseReduction => {
                    Some(CudaModulusSwitchNoiseReductionConfiguration::Centered)
                }
            };

        let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new().bootstrap_key(bsk).build();

        let message_modulus: u64 = 1 << 4;
        let input_message: u64 = 3;
        let delta: u64 = (1 << (u64::BITS - 1)) / message_modulus;
        let plaintext = Plaintext(input_message * delta);

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let gpu_keys = CudaLocalKeys::from_cpu_keys(
                    &cpu_keys,
                    modulus_switch_noise_reduction_configuration,
                    &streams,
                );

                let lwe_ciphertext_in: LweCiphertextOwned<u64> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        plaintext,
                        lwe_noise_distribution_u64,
                        ct_modulus_u64,
                        &mut encryption_generator,
                    );
                let lwe_ciphertext_in_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &streams);

                let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
                    Scalar::ONE,
                    squash_params.glwe_dimension.to_glwe_size(),
                    squash_params.polynomial_size,
                    squash_params.ciphertext_modulus,
                );
                let accumulator_gpu =
                    CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                let out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    squash_params.ciphertext_modulus,
                );
                let mut out_pbs_ct_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &streams);

                bench_id = format!("{bench_name}::{params_name}");
                println!("{bench_id}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            cuda_programmable_bootstrap_128_lwe_ciphertext(
                                &lwe_ciphertext_in_gpu,
                                &mut out_pbs_ct_gpu,
                                &accumulator_gpu,
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
                    cuda_local_keys_core(&cpu_keys, modulus_switch_noise_reduction_configuration);
                let gpu_count = get_number_of_gpus() as usize;

                bench_id = format!("{bench_name}::throughput::{params_name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                let elements_per_stream = elements as usize / gpu_count;
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let local_streams = cuda_local_streams_core();

                        let plaintext_list =
                            PlaintextList::new(u64::ZERO, PlaintextCount(elements_per_stream));

                        let input_cts = (0..gpu_count)
                            .map(|i| {
                                let mut input_ct_list = LweCiphertextList::new(
                                    u64::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(elements_per_stream),
                                    ct_modulus_u64,
                                );

                                encrypt_lwe_ciphertext_list(
                                    &input_lwe_secret_key,
                                    &mut input_ct_list,
                                    &plaintext_list,
                                    lwe_noise_distribution_u64,
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
                                    squash_params.glwe_dimension.to_glwe_size(),
                                    squash_params.polynomial_size,
                                    squash_params.ciphertext_modulus,
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
                                    squash_params.ciphertext_modulus,
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
                                    |(
                                        (((i, input_batch), output_batch), accumulator),
                                        local_stream,
                                    )| {
                                        cuda_programmable_bootstrap_128_lwe_ciphertext(
                                            input_batch,
                                            output_batch,
                                            accumulator,
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
            lwe_dimension: Some(input_params.lwe_dimension),
            glwe_dimension: Some(squash_params.glwe_dimension),
            polynomial_size: Some(squash_params.polynomial_size),
            lwe_noise_distribution: Some(lwe_noise_distribution_u64),
            glwe_noise_distribution: Some(input_params.glwe_noise_distribution),
            pbs_base_log: Some(squash_params.decomp_base_log),
            pbs_level: Some(squash_params.decomp_level_count),
            ciphertext_modulus: Some(input_params.ciphertext_modulus),
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

    fn cuda_multi_bit_pbs_128(c: &mut Criterion) {
        let bench_name = "core_crypto::cuda::multi_bit_pbs128";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(10)
            .measurement_time(std::time::Duration::from_secs(30));

        type Scalar = u128;
        let input_params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let NoiseSquashingParameters::MultiBit(squash_params) =
            NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
        else {
            panic!("Expected Multi bit params")
        };

        let lwe_noise_distribution_u64 = DynamicDistribution::new_t_uniform(46);
        let ct_modulus_u64: CiphertextModulus<u64> = CiphertextModulus::new_native();

        let params_name = "PARAMS_SWITCH_SQUASH";

        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

        let input_lwe_secret_key =
            LweSecretKey::generate_new_binary(input_params.lwe_dimension, &mut secret_generator);

        let output_glwe_secret_key = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            squash_params.glwe_dimension,
            squash_params.polynomial_size,
            &mut secret_generator,
        );

        let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

        let multi_bit_bsk = LweMultiBitBootstrapKey::new(
            Scalar::ZERO,
            squash_params.glwe_dimension.to_glwe_size(),
            squash_params.polynomial_size,
            squash_params.decomp_base_log,
            squash_params.decomp_level_count,
            input_params.lwe_dimension,
            squash_params.grouping_factor,
            squash_params.ciphertext_modulus,
        );

        let cpu_keys: CpuKeys<_> = CpuKeysBuilder::new()
            .multi_bit_bootstrap_key(multi_bit_bsk)
            .build();

        let message_modulus: u64 = 1 << 4;
        let input_message: u64 = 3;
        let delta: u64 = (1 << (u64::BITS - 1)) / message_modulus;
        let plaintext = Plaintext(input_message * delta);

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let streams = CudaStreams::new_multi_gpu();
                let gpu_keys = CudaLocalKeys::from_cpu_keys(&cpu_keys, None, &streams);

                let lwe_ciphertext_in: LweCiphertextOwned<u64> =
                    allocate_and_encrypt_new_lwe_ciphertext(
                        &input_lwe_secret_key,
                        plaintext,
                        lwe_noise_distribution_u64,
                        ct_modulus_u64,
                        &mut encryption_generator,
                    );
                let lwe_ciphertext_in_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &streams);

                let accumulator: GlweCiphertextOwned<Scalar> = GlweCiphertextOwned::new(
                    Scalar::ONE,
                    squash_params.glwe_dimension.to_glwe_size(),
                    squash_params.polynomial_size,
                    squash_params.ciphertext_modulus,
                );
                let accumulator_gpu =
                    CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &streams);

                let out_pbs_ct = LweCiphertext::new(
                    Scalar::ZERO,
                    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
                    squash_params.ciphertext_modulus,
                );
                let mut out_pbs_ct_gpu =
                    CudaLweCiphertextList::from_lwe_ciphertext(&out_pbs_ct, &streams);

                let h_indexes = [0];
                let cuda_indexes = CudaIndexes::new(&h_indexes, &streams, 0);

                bench_id = format!("{bench_name}::{params_name}");
                println!("{bench_id}");
                {
                    bench_group.bench_function(&bench_id, |b| {
                        b.iter(|| {
                            cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext(
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
            }
            BenchmarkType::Throughput => {
                let gpu_keys_vec = cuda_local_keys_core(&cpu_keys, None);
                let gpu_count = get_number_of_gpus() as usize;

                bench_id = format!("{bench_name}::throughput::{params_name}");
                println!("{bench_id}");
                let blocks: usize = 1;
                let elements = throughput_num_threads(blocks, 1);
                let elements_per_stream = elements as usize / gpu_count;
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
                    let setup_encrypted_values = || {
                        let local_streams = cuda_local_streams_core();

                        let plaintext_list =
                            PlaintextList::new(u64::ZERO, PlaintextCount(elements_per_stream));

                        let input_cts = (0..gpu_count)
                            .map(|i| {
                                let mut input_ct_list = LweCiphertextList::new(
                                    u64::ZERO,
                                    input_lwe_secret_key.lwe_dimension().to_lwe_size(),
                                    LweCiphertextCount(elements_per_stream),
                                    ct_modulus_u64,
                                );

                                encrypt_lwe_ciphertext_list(
                                    &input_lwe_secret_key,
                                    &mut input_ct_list,
                                    &plaintext_list,
                                    lwe_noise_distribution_u64,
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
                                    squash_params.glwe_dimension.to_glwe_size(),
                                    squash_params.polynomial_size,
                                    squash_params.ciphertext_modulus,
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
                                    squash_params.ciphertext_modulus,
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
                                    |((((i, input_ct), output_ct), accumulator), local_stream)| {
                                        cuda_multi_bit_programmable_bootstrap_128_lwe_ciphertext(
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

        let params_record = CryptoParametersRecord {
            lwe_dimension: Some(input_params.lwe_dimension),
            glwe_dimension: Some(squash_params.glwe_dimension),
            polynomial_size: Some(squash_params.polynomial_size),
            lwe_noise_distribution: Some(lwe_noise_distribution_u64),
            glwe_noise_distribution: Some(input_params.glwe_noise_distribution),
            pbs_base_log: Some(squash_params.decomp_base_log),
            pbs_level: Some(squash_params.decomp_level_count),
            ciphertext_modulus: Some(input_params.ciphertext_modulus),
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

    pub fn cuda_multi_bit_pbs128_group() {
        let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
        cuda_multi_bit_pbs_128(&mut criterion);
    }
}

#[cfg(feature = "gpu")]
use cuda::{cuda_multi_bit_pbs128_group, cuda_pbs128_group};

pub fn pbs128_group() {
    let mut criterion: Criterion<_> = Criterion::default().configure_from_args();
    pbs_128(&mut criterion);
}

#[cfg(feature = "gpu")]
fn go_through_gpu_bench_groups() {
    cuda_pbs128_group();
    cuda_multi_bit_pbs128_group();
}

#[cfg(not(feature = "gpu"))]
fn go_through_cpu_bench_groups() {
    pbs128_group();
}
fn main() {
    #[cfg(feature = "gpu")]
    go_through_gpu_bench_groups();
    #[cfg(not(feature = "gpu"))]
    go_through_cpu_bench_groups();

    Criterion::default().configure_from_args().final_summary();
}
