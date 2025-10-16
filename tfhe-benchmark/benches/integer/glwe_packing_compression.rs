use benchmark::params_aliases::*;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rayon::prelude::*;
use std::cmp::max;
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::keycache::NamedParam;
use tfhe::{get_pbs_count, reset_pbs_count};

fn cpu_glwe_packing(c: &mut Criterion) {
    let bench_name = "integer::packing_compression";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let cks = ClientKey::new(param);

    let private_compression_key = cks.new_compression_private_key(comp_param);

    let (compression_key, decompression_key) =
        cks.new_compression_decompression_keys(&private_compression_key);

    let log_message_modulus = param.message_modulus.0.ilog2() as usize;

    for bit_size in [
        2,
        8,
        16,
        32,
        64,
        128,
        256,
        comp_param.lwe_per_glwe().0 * log_message_modulus,
    ] {
        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_pack;
        let bench_id_unpack;

        match get_bench_type() {
            BenchmarkType::Latency => {
                let ct = cks.encrypt_radix(0_u32, num_blocks);

                let mut builder = CompressedCiphertextListBuilder::new();

                builder.push(ct);

                bench_id_pack = format!("{bench_name}::pack_u{bit_size}");
                bench_group.bench_function(&bench_id_pack, |b| {
                    b.iter(|| {
                        let compressed = builder.build(&compression_key);

                        _ = black_box(compressed);
                    })
                });

                let compressed = builder.build(&compression_key);

                bench_id_unpack = format!("{bench_name}::unpack_u{bit_size}");
                bench_group.bench_function(&bench_id_unpack, |b| {
                    b.iter(|| {
                        let unpacked: RadixCiphertext =
                            compressed.get(0, &decompression_key).unwrap().unwrap();

                        _ = black_box(unpacked);
                    })
                });
            }
            BenchmarkType::Throughput => {
                // Execute the operation once to know its cost.
                let ct = cks.encrypt_radix(0_u32, num_blocks);
                let mut builder = CompressedCiphertextListBuilder::new();
                builder.push(ct);
                let compressed = builder.build(&compression_key);

                reset_pbs_count();
                let _: RadixCiphertext = compressed.get(0, &decompression_key).unwrap().unwrap();
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                let num_block =
                    (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;
                let elements = throughput_num_threads(num_block, pbs_count);
                // FIXME thread usage seemed to be somewhat more "efficient".
                //  For example, with bit_size = 2, my laptop is only using around 2/3 of the
                // available threads  Thread usage increases with bit_size = 8 but
                // still isn't fully loaded.
                bench_group.throughput(Throughput::Elements(elements));

                let builders = (0..elements)
                    .map(|_| {
                        let ct = cks.encrypt_radix(0_u32, num_blocks);
                        let mut builder = CompressedCiphertextListBuilder::new();
                        builder.push(ct);

                        builder
                    })
                    .collect::<Vec<_>>();

                bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                bench_group.bench_function(&bench_id_pack, |b| {
                    b.iter(|| {
                        builders.par_iter().for_each(|builder| {
                            builder.build(&compression_key);
                        })
                    })
                });

                let compressed = builders
                    .iter()
                    .map(|builder| builder.build(&compression_key))
                    .collect::<Vec<_>>();

                bench_id_unpack = format!("{bench_name}::throughput::unpack_u{bit_size}");
                bench_group.bench_function(&bench_id_unpack, |b| {
                    b.iter(|| {
                        compressed.par_iter().for_each(|comp| {
                            comp.get::<RadixCiphertext>(0, &decompression_key)
                                .unwrap()
                                .unwrap();
                        })
                    })
                });
            }
        }

        write_to_json::<u64, _>(
            &bench_id_pack,
            (comp_param, param.into()),
            comp_param.name(),
            "pack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );

        write_to_json::<u64, _>(
            &bench_id_unpack,
            (comp_param, param.into()),
            comp_param.name(),
            "unpack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );
    }

    bench_group.finish()
}

#[cfg(feature = "gpu")]
mod cuda {
    use super::*;
    use benchmark::utilities::cuda_integer_utils::cuda_local_streams;
    use itertools::Itertools;
    use std::cmp::max;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::ciphertext::NoiseSquashingCompressionPrivateKey;
    use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    use tfhe::integer::gpu::ciphertext::squashed_noise::CudaSquashedNoiseRadixCiphertext;
    use tfhe::integer::gpu::ciphertext::{
        CudaCompressedSquashedNoiseCiphertextList, CudaUnsignedRadixCiphertext,
    };
    use tfhe::integer::gpu::gen_keys_radix_gpu;
    use tfhe::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
    use tfhe::integer::noise_squashing::NoiseSquashingPrivateKey;

    fn gpu_glwe_packing(c: &mut Criterion) {
        let bench_name = "integer::cuda::packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let comp_param =
            BENCH_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let log_message_modulus = param.message_modulus.0.ilog2() as usize;

        let cks = ClientKey::new(param);
        let private_compression_key = cks.new_compression_private_key(comp_param);

        for bit_size in [
            2,
            8,
            16,
            32,
            64,
            128,
            256,
            comp_param.lwe_per_glwe().0 * log_message_modulus,
        ] {
            assert_eq!(bit_size % log_message_modulus, 0);
            let num_blocks = bit_size / log_message_modulus;

            let bench_id_pack;
            let bench_id_unpack;

            // Generate and convert compression keys
            let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
            let (compressed_compression_key, compressed_decompression_key) =
                radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let cuda_compression_key =
                        compressed_compression_key.decompress_to_cuda(&stream);
                    let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
                        radix_cks.parameters().glwe_dimension(),
                        radix_cks.parameters().polynomial_size(),
                        radix_cks.parameters().message_modulus(),
                        radix_cks.parameters().carry_modulus(),
                        radix_cks.parameters().ciphertext_modulus(),
                        &stream,
                    );

                    // Encrypt
                    let ct = cks.encrypt_radix(0_u32, num_blocks);
                    let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);

                    // Benchmark
                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    builder.push(d_ct, &stream);

                    bench_id_pack = format!("{bench_name}::pack_u{bit_size}");
                    bench_group.bench_function(&bench_id_pack, |b| {
                        b.iter(|| {
                            let compressed = builder.build(&cuda_compression_key, &stream);

                            _ = black_box(compressed);
                        })
                    });

                    let compressed = builder.build(&cuda_compression_key, &stream);

                    bench_id_unpack = format!("{bench_name}::unpack_u{bit_size}");
                    bench_group.bench_function(&bench_id_unpack, |b| {
                        b.iter(|| {
                            let unpacked: CudaUnsignedRadixCiphertext = compressed
                                .get(0, &cuda_decompression_key, &stream)
                                .unwrap()
                                .unwrap();

                            _ = black_box(unpacked);
                        })
                    });
                }
                BenchmarkType::Throughput => {
                    // Execute the operation once to know its cost.
                    let (cpu_compression_key, cpu_decompression_key) =
                        cks.new_compression_decompression_keys(&private_compression_key);
                    let ct = cks.encrypt_radix(0_u32, num_blocks);
                    let mut builder = CompressedCiphertextListBuilder::new();
                    builder.push(ct);
                    let compressed = builder.build(&cpu_compression_key);

                    reset_pbs_count();
                    // Use CPU operation as pbs_count do not count PBS on GPU backend.
                    let _: RadixCiphertext =
                        compressed.get(0, &cpu_decompression_key).unwrap().unwrap();
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    let num_block = (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0))
                        .ceil() as usize;
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));

                    // Encrypt
                    let local_streams = cuda_local_streams(num_block, elements as usize);

                    let cuda_compression_key_vec = local_streams
                        .iter()
                        .map(|local_stream| {
                            compressed_compression_key.decompress_to_cuda(local_stream)
                        })
                        .collect_vec();
                    let cuda_decompression_key_vec = local_streams
                        .iter()
                        .map(|local_stream| {
                            compressed_decompression_key.decompress_to_cuda(
                                radix_cks.parameters().glwe_dimension(),
                                radix_cks.parameters().polynomial_size(),
                                radix_cks.parameters().message_modulus(),
                                radix_cks.parameters().carry_modulus(),
                                radix_cks.parameters().ciphertext_modulus(),
                                local_stream,
                            )
                        })
                        .collect_vec();

                    // Benchmark
                    let builders = (0..elements)
                        .map(|i| {
                            let ct = cks.encrypt_radix(0_u32, num_blocks);
                            let local_stream = &local_streams[i as usize % local_streams.len()];
                            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct,
                                local_stream,
                            );
                            let mut builder = CudaCompressedCiphertextListBuilder::new();
                            builder.push(d_ct, local_stream);

                            builder
                        })
                        .collect::<Vec<_>>();

                    bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                    bench_group.bench_function(&bench_id_pack, |b| {
                        b.iter(|| {
                            builders.par_iter().enumerate().for_each(|(i, builder)| {
                                let local_stream = &local_streams[i % local_streams.len()];
                                let cuda_compression_key =
                                    &cuda_compression_key_vec[i % local_streams.len()];

                                builder.build(cuda_compression_key, local_stream);
                            })
                        })
                    });

                    let compressed = builders
                        .iter()
                        .enumerate()
                        .map(|(i, builder)| {
                            let local_stream = &local_streams[i % local_streams.len()];
                            let cuda_compression_key =
                                &cuda_compression_key_vec[i % local_streams.len()];
                            builder.build(cuda_compression_key, local_stream)
                        })
                        .collect::<Vec<_>>();

                    bench_id_unpack = format!("{bench_name}::throughput::unpack_u{bit_size}");
                    bench_group.bench_function(&bench_id_unpack, |b| {
                        b.iter(|| {
                            compressed.par_iter().enumerate().for_each(|(i, comp)| {
                                let local_stream = &local_streams[i % local_streams.len()];
                                let cuda_decompression_key =
                                    &cuda_decompression_key_vec[i % local_streams.len()];

                                comp.get::<CudaUnsignedRadixCiphertext>(
                                    0,
                                    cuda_decompression_key,
                                    local_stream,
                                )
                                .unwrap()
                                .unwrap();
                            })
                        })
                    });
                }
            }

            write_to_json::<u64, _>(
                &bench_id_pack,
                (comp_param, param.into()),
                comp_param.name(),
                "pack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );

            write_to_json::<u64, _>(
                &bench_id_unpack,
                (comp_param, param.into()),
                comp_param.name(),
                "unpack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );
        }

        bench_group.finish()
    }

    fn gpu_glwe_packing_128(c: &mut Criterion) {
        let bench_name = "integer::cuda::128b_packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_compression_parameters =
            BENCH_COMP_NOISE_SQUASHING_PARAM_GPU_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let noise_squashing_parameters =
            BENCH_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let log_message_modulus = param.message_modulus.0.ilog2() as usize;

        let noise_squashing_compression_private_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_parameters);
        let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
        let noise_squashing_compression_key = noise_squashing_private_key
            .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
        let cuda_noise_squashing_compression_key =
            CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                &noise_squashing_compression_key,
                &stream,
            );

        for bit_size in [
            2,
            8,
            16,
            32,
            64,
            128,
            // we don't need 256 here since
            // noise_squashing_compression_parameters.lwe_per_glwe.0 * log_message_modulus == 256
            // with current parameters 256,
            noise_squashing_compression_parameters.lwe_per_glwe.0 * log_message_modulus,
        ] {
            assert_eq!(bit_size % log_message_modulus, 0);
            let num_blocks = bit_size / log_message_modulus;

            let bench_id_pack;
            let bench_id_unpack;

            // Generate and convert compression keys
            let cks = ClientKey::new(param);
            let (_, cuda_sks) = gen_keys_radix_gpu(param, num_blocks, &stream);
            let compressed_noise_squashing_compression_key =
                cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let cuda_noise_squashing_key =
                        compressed_noise_squashing_compression_key.decompress_to_cuda(&stream);

                    // Encrypt
                    let ct = cks.encrypt_radix(0_u32, num_blocks);
                    let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);
                    let d_ns_ct = cuda_noise_squashing_key
                        .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &stream)
                        .unwrap();

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
                    let num_block = (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0))
                        .ceil() as usize;
                    let elements = 100;
                    bench_group.throughput(Throughput::Elements(elements));

                    // Encrypt
                    let local_streams = cuda_local_streams(num_block, elements as usize);

                    let cuda_compression_key_vec = local_streams
                        .iter()
                        .map(|local_stream| {
                            compressed_noise_squashing_compression_key
                                .decompress_to_cuda(local_stream)
                        })
                        .collect_vec();

                    let cuda_noise_squashing_compression_key =
                        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
                            &noise_squashing_compression_key,
                            &stream,
                        );

                    // Benchmark
                    let builders = (0..elements)
                        .map(|i| {
                            let ct = cks.encrypt_radix(0_u32, num_blocks);
                            let local_stream = &local_streams[i as usize % local_streams.len()];
                            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                                &ct,
                                local_stream,
                            );
                            let cuda_noise_squashing_key =
                                &cuda_compression_key_vec[(i as usize) % local_streams.len()];
                            let d_ns_ct = cuda_noise_squashing_key
                                .squash_radix_ciphertext_noise(&cuda_sks, &d_ct.ciphertext, &stream)
                                .unwrap();
                            let mut builder = CudaCompressedSquashedNoiseCiphertextList::builder();
                            builder.push(d_ns_ct, local_stream);

                            builder
                        })
                        .collect::<Vec<_>>();

                    bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                    bench_group.bench_function(&bench_id_pack, |b| {
                        b.iter(|| {
                            builders.par_iter().enumerate().for_each(|(i, builder)| {
                                let local_stream = &local_streams[i % local_streams.len()];

                                builder.build(&cuda_noise_squashing_compression_key, local_stream);
                            })
                        })
                    });

                    let compressed = builders
                        .iter()
                        .enumerate()
                        .map(|(i, builder)| {
                            let local_stream = &local_streams[i % local_streams.len()];

                            builder.build(&cuda_noise_squashing_compression_key, local_stream)
                        })
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
                &bench_id_pack,
                (noise_squashing_compression_parameters, param.into()),
                noise_squashing_compression_parameters.name(),
                "pack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );

            write_to_json::<u64, _>(
                &bench_id_unpack,
                (noise_squashing_compression_parameters, param.into()),
                noise_squashing_compression_parameters.name(),
                "unpack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );
        }

        bench_group.finish()
    }

    criterion_group!(gpu_glwe_packing2, gpu_glwe_packing);
    criterion_group!(gpu_glwe_packing_128_2, gpu_glwe_packing_128);
}

criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

#[cfg(feature = "gpu")]
use cuda::{gpu_glwe_packing2, gpu_glwe_packing_128_2};

fn main() {
    #[cfg(feature = "gpu")]
    gpu_glwe_packing2();
    #[cfg(feature = "gpu")]
    gpu_glwe_packing_128_2();
    #[cfg(not(feature = "gpu"))]
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
