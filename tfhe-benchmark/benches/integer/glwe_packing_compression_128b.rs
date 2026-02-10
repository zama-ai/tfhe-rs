#[cfg(feature = "gpu")]
mod cuda {
    use benchmark::params_aliases::*;
    use benchmark::utilities::cuda_integer_utils::cuda_local_streams;
    use benchmark::utilities::{
        cuda_local_keys, get_bench_type, write_to_json, BenchmarkType, OperatorType,
    };
    use criterion::{black_box, criterion_group, Criterion, Throughput};
    use rayon::prelude::*;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::ciphertext::{
        NoiseSquashingCompressionKey, NoiseSquashingCompressionPrivateKey,
    };
    use tfhe::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
    use tfhe::integer::gpu::ciphertext::{
        CudaCompressedSquashedNoiseCiphertextList, CudaUnsignedRadixCiphertext,
    };
    use tfhe::integer::gpu::gen_keys_radix_gpu;
    use tfhe::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
    use tfhe::integer::gpu::noise_squashing::keys::CudaNoiseSquashingKey;
    use tfhe::integer::noise_squashing::{CompressedNoiseSquashingKey, NoiseSquashingPrivateKey};
    use tfhe::integer::ClientKey;
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::parameters::NoiseSquashingCompressionParameters;
    use tfhe::shortint::PBSParameters;

    #[derive(Clone)]
    struct BenchConfig {
        param: PBSParameters,
        noise_squashing_compression_parameters: NoiseSquashingCompressionParameters,
        noise_squashing_compression_key: NoiseSquashingCompressionKey,
        compressed_noise_squashing_compression_key: CompressedNoiseSquashingKey,
        bit_size: usize,
        cks: ClientKey,
    }

    fn get_num_elements_per_gpu(_bit_size: usize) -> usize {
        // 200 elements per GPU seems enough to saturate H100s
        // This is an empirical value and might need to be adjusted in the future
        200
    }

    fn execute_gpu_glwe_packing_128(c: &mut Criterion, config: BenchConfig) {
        let bench_name = "integer::cuda::128b_packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let BenchConfig {
            param,
            noise_squashing_compression_parameters,
            noise_squashing_compression_key,
            compressed_noise_squashing_compression_key,
            bit_size,
            cks,
        } = config;

        let log_message_modulus = param.message_modulus().0.ilog2() as usize;

        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_pack;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let (_, cuda_sks) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let cuda_noise_squashing_key =
                    compressed_noise_squashing_compression_key.decompress_to_cuda(&stream);

                // Encrypt
                let ct = cks.encrypt_radix(0_u32, num_blocks);
                let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);
                let d_ns_ct = cuda_noise_squashing_key
                    .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &stream)
                    .unwrap();
                let cuda_noise_squashing_compression_key =
                    CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                        &noise_squashing_compression_key,
                        &stream,
                    );

                // Benchmark
                let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                builder.push(d_ns_ct, &stream);

                bench_id_pack = format!("{bench_name}::pack_u{bit_size}");
                bench_group.bench_function(&bench_id_pack, |b| {
                    b.iter(|| {
                        let compressed =
                            builder.build(&cuda_noise_squashing_compression_key, &stream);

                        _ = black_box(compressed);
                    })
                });
            }
            BenchmarkType::Throughput => {
                let cuda_sks = cuda_local_keys(&cks);
                let num_block =
                    (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;
                let elements = get_num_elements_per_gpu(bit_size) as u64;
                bench_group.throughput(Throughput::Elements(elements));

                // Encrypt
                let local_streams = cuda_local_streams(num_block, elements as usize);

                let num_gpus = get_number_of_gpus() as usize;

                let cuda_compression_key_vec: Vec<CudaNoiseSquashingKey> = (0..num_gpus)
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        compressed_noise_squashing_compression_key.decompress_to_cuda(local_stream)
                    })
                    .collect();
                let cuda_noise_squashing_compression_key_vec: Vec<
                    CudaNoiseSquashingCompressionKey,
                > = (0..num_gpus)
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                            &noise_squashing_compression_key,
                            local_stream,
                        )
                    })
                    .collect();

                // Benchmark
                let builders = (0..elements)
                    .into_par_iter()
                    .map(|i| {
                        let ct = cks.encrypt_radix(0_u32, num_blocks);
                        let local_stream = &local_streams[i as usize % local_streams.len()];
                        let d_ct =
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, local_stream);
                        let cuda_noise_squashing_key =
                            &cuda_compression_key_vec[(i as usize) % num_gpus];
                        let cuda_noise_squashing_compression_key =
                            &cuda_noise_squashing_compression_key_vec[(i as usize) % num_gpus];
                        let d_ns_ct = cuda_noise_squashing_key
                            .squash_radix_ciphertext_noise(
                                &cuda_sks[(i as usize) % num_gpus],
                                &d_ct.ciphertext,
                                local_stream,
                            )
                            .unwrap();
                        let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();
                        builder.push(d_ns_ct, local_stream);

                        (builder, cuda_noise_squashing_compression_key, local_stream)
                    })
                    .collect::<Vec<_>>();

                bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                bench_group.bench_function(&bench_id_pack, |b| {
                    b.iter(|| {
                        builders.par_iter().for_each(
                            |(builder, cuda_noise_squashing_compression_key, local_stream)| {
                                builder.build(cuda_noise_squashing_compression_key, local_stream);
                            },
                        )
                    })
                });
            }
        }

        write_to_json::<u64, _>(
            &bench_id_pack,
            (noise_squashing_compression_parameters, param.into()),
            noise_squashing_compression_parameters.name(),
            "pack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_blocks],
        );

        bench_group.finish()
    }

    fn execute_gpu_glwe_unpacking_128(c: &mut Criterion, config: BenchConfig) {
        let bench_name = "integer::cuda::128b_packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let BenchConfig {
            param,
            noise_squashing_compression_parameters,
            noise_squashing_compression_key,
            compressed_noise_squashing_compression_key,
            bit_size,
            cks,
        } = config;

        let log_message_modulus = param.message_modulus().0.ilog2() as usize;

        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_unpack;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let (_, cuda_sks) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let cuda_noise_squashing_key =
                    compressed_noise_squashing_compression_key.decompress_to_cuda(&stream);

                // Encrypt
                let ct = cks.encrypt_radix(0_u32, num_blocks);
                let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);
                let d_ns_ct = cuda_noise_squashing_key
                    .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &stream)
                    .unwrap();
                let cuda_noise_squashing_compression_key =
                    CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                        &noise_squashing_compression_key,
                        &stream,
                    );

                // Benchmark
                let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();

                builder.push(d_ns_ct, &stream);

                let compressed = builder.build(&cuda_noise_squashing_compression_key, &stream);

                bench_id_unpack = format!("{bench_name}::unpack_u{bit_size}");
                bench_group.bench_function(&bench_id_unpack, |b| {
                    b.iter(|| {
                        let unpacked: CudaSquashedNoiseRadixCiphertext =
                            compressed.get(0, &stream).unwrap().unwrap();

                        _ = black_box(unpacked);
                    })
                });
            }
            BenchmarkType::Throughput => {
                let cuda_sks = cuda_local_keys(&cks);
                let num_block =
                    (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;
                let elements = get_num_elements_per_gpu(bit_size) as u64;
                bench_group.throughput(Throughput::Elements(elements));

                // Encrypt
                let local_streams = cuda_local_streams(num_block, elements as usize);

                let num_gpus = get_number_of_gpus() as usize;

                let cuda_compression_key_vec: Vec<CudaNoiseSquashingKey> = (0..num_gpus)
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        compressed_noise_squashing_compression_key.decompress_to_cuda(local_stream)
                    })
                    .collect();
                let cuda_noise_squashing_compression_key_vec: Vec<
                    CudaNoiseSquashingCompressionKey,
                > = (0..num_gpus)
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                            &noise_squashing_compression_key,
                            local_stream,
                        )
                    })
                    .collect();

                // Benchmark
                let builders = (0..elements)
                    .into_par_iter()
                    .map(|i| {
                        let ct = cks.encrypt_radix(0_u32, num_blocks);
                        let local_stream = &local_streams[i as usize % local_streams.len()];
                        let d_ct =
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, local_stream);
                        let cuda_noise_squashing_key =
                            &cuda_compression_key_vec[(i as usize) % num_gpus];
                        let cuda_noise_squashing_compression_key =
                            &cuda_noise_squashing_compression_key_vec[(i as usize) % num_gpus];
                        let d_ns_ct = cuda_noise_squashing_key
                            .squash_radix_ciphertext_noise(
                                &cuda_sks[(i as usize) % num_gpus],
                                &d_ct.ciphertext,
                                local_stream,
                            )
                            .unwrap();
                        let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();
                        builder.push(d_ns_ct, local_stream);

                        (builder, cuda_noise_squashing_compression_key, local_stream)
                    })
                    .collect::<Vec<_>>();

                let compressed = builders
                    .into_par_iter()
                    .map(
                        |(builder, cuda_noise_squashing_compression_key, local_stream)| {
                            builder.build(cuda_noise_squashing_compression_key, local_stream)
                        },
                    )
                    .collect::<Vec<_>>();

                bench_id_unpack = format!("{bench_name}::throughput::unpack_u{bit_size}");
                bench_group.bench_function(&bench_id_unpack, |b| {
                    b.iter(|| {
                        compressed.par_iter().enumerate().for_each(|(i, comp)| {
                            let local_stream = &local_streams[i % local_streams.len()];

                            comp.get::<CudaSquashedNoiseRadixCiphertext>(0, local_stream)
                                .unwrap()
                                .unwrap();
                        })
                    })
                });
            }
        }

        write_to_json::<u64, _>(
            &bench_id_unpack,
            (noise_squashing_compression_parameters, param.into()),
            noise_squashing_compression_parameters.name(),
            "unpack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_blocks],
        );

        bench_group.finish()
    }

    fn gpu_glwe_packing_128(c: &mut Criterion) {
        let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_parameters =
            BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let log_message_modulus = param.message_modulus.0.ilog2() as usize;

        let cks = ClientKey::new(param);

        let noise_squashing_compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_parameters);
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let noise_squashing_compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);

        // Generate and convert compression keys
        let compressed_noise_squashing_compression_key =
            cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

        let mut config = BenchConfig {
            param: PBSParameters::PBS(param),
            noise_squashing_compression_key,
            noise_squashing_compression_parameters,
            compressed_noise_squashing_compression_key,
            bit_size: 0,
            cks,
        };
        for bit_size in [
            2,
            8,
            16,
            32,
            64,
            128,
            256,
            noise_squashing_compression_parameters.lwe_per_glwe.0 * log_message_modulus,
        ] {
            config.bit_size = bit_size;
            execute_gpu_glwe_packing_128(c, config.clone());
        }
    }

    fn gpu_glwe_unpacking_128(c: &mut Criterion) {
        let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_parameters =
            BENCH_COMP_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let log_message_modulus = param.message_modulus.0.ilog2() as usize;

        let cks = ClientKey::new(param);

        let noise_squashing_compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_parameters);
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let noise_squashing_compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);

        // Generate and convert compression keys
        let compressed_noise_squashing_compression_key =
            cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

        let mut config = BenchConfig {
            param: PBSParameters::PBS(param),
            noise_squashing_compression_key,
            noise_squashing_compression_parameters,
            compressed_noise_squashing_compression_key,
            bit_size: 0,
            cks,
        };
        for bit_size in [
            2,
            8,
            16,
            32,
            64,
            128,
            256,
            noise_squashing_compression_parameters.lwe_per_glwe.0 * log_message_modulus,
        ] {
            config.bit_size = bit_size;
            execute_gpu_glwe_unpacking_128(c, config.clone());
        }
    }

    criterion_group!(gpu_glwe_packing_128_2, gpu_glwe_packing_128);
    criterion_group!(gpu_glwe_unpacking_128_2, gpu_glwe_unpacking_128);
}

use criterion::Criterion;
#[cfg(feature = "gpu")]
use cuda::gpu_glwe_packing_128_2;
#[cfg(feature = "gpu")]
use cuda::gpu_glwe_unpacking_128_2;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_glwe_packing_128_2();
    #[cfg(feature = "gpu")]
    gpu_glwe_unpacking_128_2();
    Criterion::default().configure_from_args().final_summary();
}
