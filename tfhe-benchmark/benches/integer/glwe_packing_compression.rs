use benchmark::params_aliases::*;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, BitSizesSet, EnvConfig,
    OperatorType,
};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rayon::prelude::*;
use std::cmp::max;
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::LweCiphertextCount;
use tfhe::shortint::MessageModulus;
use tfhe::{get_pbs_count, reset_pbs_count};

fn default_config(
    lwe_per_glwe: &LweCiphertextCount,
    message_modulus: &MessageModulus,
) -> Vec<usize> {
    let env_config = EnvConfig::new();

    match env_config.bit_sizes_set {
        BitSizesSet::Fast => {
            vec![64]
        }
        _ => {
            vec![
                2,
                8,
                16,
                32,
                64,
                128,
                256,
                lwe_per_glwe.0 * message_modulus.0.ilog2() as usize,
            ]
        }
    }
}

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

    for bit_size in default_config(&comp_param.lwe_per_glwe(), &param.message_modulus) {
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
    use benchmark::utilities::{get_param_type, ParamType};
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::compression_keys::CompressionPrivateKeys;
    use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::gen_keys_radix_gpu;
    use tfhe::shortint::parameters::CompressionParameters;

    #[derive(Clone)]
    struct BenchConfig {
        param: tfhe::shortint::AtomicPatternParameters,
        comp_param: CompressionParameters,
        bit_size: usize,
        cks: ClientKey,
        private_compression_key: CompressionPrivateKeys,
    }

    fn get_num_elements_per_gpu(_bit_size: usize) -> usize {
        // 200 elements per GPU seems enough to saturate H100s
        // This is an empirical value and might need to be adjusted in the future
        200
    }

    fn execute_gpu_glwe_packing(c: &mut Criterion, config: BenchConfig) {
        let bench_name = "integer::cuda::packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let BenchConfig {
            param,
            comp_param,
            bit_size,
            cks,
            private_compression_key,
        } = config;

        let log_message_modulus = param.message_modulus().0.ilog2() as usize;

        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_pack;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Generate and convert compression keys
                let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let (compressed_compression_key, _) = radix_cks
                    .new_compressed_compression_decompression_keys(&private_compression_key);

                let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&stream);

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
            }
            BenchmarkType::Throughput => {
                // Generate and convert compression keys
                let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let (compressed_compression_key, _) = radix_cks
                    .new_compressed_compression_decompression_keys(&private_compression_key);

                let elements_per_gpu = get_num_elements_per_gpu(bit_size) as u64;
                let elements = elements_per_gpu * get_number_of_gpus() as u64;

                let num_block =
                    (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;
                bench_group.throughput(Throughput::Elements(elements));

                // Encrypt
                let local_streams = cuda_local_streams(num_block, elements as usize);

                bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                let cuda_compression_key_vec = (0..get_number_of_gpus())
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i as usize];
                        compressed_compression_key.decompress_to_cuda(local_stream)
                    })
                    .collect::<Vec<_>>();

                // Benchmark
                let builders = (0..elements)
                    .into_par_iter()
                    .map(|i| {
                        let ct = cks.encrypt_radix(0_u32, num_blocks);
                        let local_stream = &local_streams[i as usize % local_streams.len()];
                        let d_ct =
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, local_stream);
                        let mut builder = CudaCompressedCiphertextListBuilder::new();
                        builder.push(d_ct, local_stream);

                        builder
                    })
                    .collect::<Vec<_>>();

                bench_group.bench_function(&bench_id_pack, |b| {
                    b.iter(|| {
                        builders.par_iter().enumerate().for_each(|(i, builder)| {
                            let local_stream = &local_streams[i % local_streams.len()];
                            let cuda_compression_key =
                                &cuda_compression_key_vec[i % get_number_of_gpus() as usize];

                            let _ = builder.build(cuda_compression_key, local_stream);
                        })
                    })
                });
            }
        }

        write_to_json::<u64, _>(
            &bench_id_pack,
            (comp_param, param),
            comp_param.name(),
            "pack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_blocks],
        );

        bench_group.finish()
    }

    fn execute_gpu_glwe_unpacking(c: &mut Criterion, config: BenchConfig) {
        let bench_name = "integer::cuda::packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let BenchConfig {
            param,
            comp_param,
            bit_size,
            cks,
            private_compression_key,
        } = config;

        let log_message_modulus = param.message_modulus().0.ilog2() as usize;

        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_unpack;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Generate and convert compression keys
                let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let (compressed_compression_key, compressed_decompression_key) = radix_cks
                    .new_compressed_compression_decompression_keys(&private_compression_key);

                let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&stream);
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
                // Generate and convert compression keys
                let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
                let (compressed_compression_key, compressed_decompression_key) = radix_cks
                    .new_compressed_compression_decompression_keys(&private_compression_key);

                let elements_per_gpu = get_num_elements_per_gpu(bit_size) as u64;
                let elements = elements_per_gpu * get_number_of_gpus() as u64;

                let num_block =
                    (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;
                bench_group.throughput(Throughput::Elements(elements));

                // Encrypt
                let local_streams = cuda_local_streams(num_block, elements as usize);

                bench_id_unpack = format!("{bench_name}::throughput::unpack_u{bit_size}");
                let builders = (0..elements)
                    .into_par_iter()
                    .map(|i| {
                        let ct = cks.encrypt_radix(0_u32, num_blocks);
                        let local_stream = &local_streams[i as usize % local_streams.len()];
                        let d_ct =
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, local_stream);
                        let mut builder = CudaCompressedCiphertextListBuilder::new();
                        builder.push(d_ct, local_stream);

                        builder
                    })
                    .collect::<Vec<_>>();

                let cuda_compression_key_vec = (0..get_number_of_gpus())
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i as usize];
                        compressed_compression_key.decompress_to_cuda(local_stream)
                    })
                    .collect::<Vec<_>>();

                let cuda_decompression_key_vec = (0..get_number_of_gpus())
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &local_streams[i as usize];
                        compressed_decompression_key.decompress_to_cuda(
                            radix_cks.parameters().glwe_dimension(),
                            radix_cks.parameters().polynomial_size(),
                            radix_cks.parameters().message_modulus(),
                            radix_cks.parameters().carry_modulus(),
                            radix_cks.parameters().ciphertext_modulus(),
                            local_stream,
                        )
                    })
                    .collect::<Vec<_>>();

                let compressed = builders
                    .par_iter()
                    .enumerate()
                    .map(|(i, builder)| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        let cuda_compression_key =
                            &cuda_compression_key_vec[i % get_number_of_gpus() as usize];
                        builder.build(cuda_compression_key, local_stream)
                    })
                    .collect::<Vec<_>>();

                bench_group.bench_function(&bench_id_unpack, |b| {
                    b.iter(|| {
                        compressed.par_iter().enumerate().for_each(|(i, comp)| {
                            let local_stream = &local_streams[i % local_streams.len()];
                            let cuda_decompression_key =
                                &cuda_decompression_key_vec[i % get_number_of_gpus() as usize];

                            let _ = comp
                                .get::<CudaUnsignedRadixCiphertext>(
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
            &bench_id_unpack,
            (comp_param, param),
            comp_param.name(),
            "unpack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_blocks],
        );

        bench_group.finish()
    }

    fn gpu_glwe_packing(c: &mut Criterion) {
        let (param, comp_param): (
            tfhe::shortint::AtomicPatternParameters,
            CompressionParameters,
        ) = match get_param_type() {
            ParamType::Classical => (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            _ => (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        };

        let cks = ClientKey::new(param);
        let private_compression_key = cks.new_compression_private_key(comp_param);

        let mut config = BenchConfig {
            param,
            comp_param,
            cks,
            private_compression_key,
            bit_size: 0,
        };
        for bit_size in default_config(&comp_param.lwe_per_glwe(), &param.message_modulus()) {
            config.bit_size = bit_size;
            execute_gpu_glwe_packing(c, config.clone());
        }
    }

    fn gpu_glwe_unpacking(c: &mut Criterion) {
        let (param, comp_param): (
            tfhe::shortint::AtomicPatternParameters,
            CompressionParameters,
        ) = match get_param_type() {
            ParamType::Classical => (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
            _ => (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ),
        };

        let cks = ClientKey::new(param);
        let private_compression_key = cks.new_compression_private_key(comp_param);

        let mut config = BenchConfig {
            param,
            comp_param,
            bit_size: 0,
            cks,
            private_compression_key,
        };
        for bit_size in default_config(&comp_param.lwe_per_glwe(), &param.message_modulus()) {
            config.bit_size = bit_size;
            execute_gpu_glwe_unpacking(c, config.clone());
        }
    }

    criterion_group!(gpu_glwe_packing2, gpu_glwe_packing);
    criterion_group!(gpu_glwe_unpacking2, gpu_glwe_unpacking);
}

criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

#[cfg(feature = "gpu")]
use cuda::gpu_glwe_packing2;
#[cfg(feature = "gpu")]
use cuda::gpu_glwe_unpacking2;

fn main() {
    #[cfg(feature = "gpu")]
    {
        gpu_glwe_packing2();
        gpu_glwe_unpacking2();
    }
    #[cfg(not(feature = "gpu"))]
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
