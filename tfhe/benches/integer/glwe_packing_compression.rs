#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{
    throughput_num_threads, write_to_json, BenchmarkType, OperatorType, BENCH_TYPE,
};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rayon::prelude::*;
use std::cmp::max;
use tfhe::integer::ciphertext::CompressedCiphertextListBuilder;
use tfhe::integer::{ClientKey, RadixCiphertext};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

fn cpu_glwe_packing(c: &mut Criterion) {
    let bench_name = "integer::packing_compression";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

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
        comp_param.lwe_per_glwe.0 * log_message_modulus,
    ] {
        assert_eq!(bit_size % log_message_modulus, 0);
        let num_blocks = bit_size / log_message_modulus;

        let bench_id_pack;
        let bench_id_unpack;

        match BENCH_TYPE.get().unwrap() {
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
            (comp_param, param),
            comp_param.name(),
            "pack",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );

        write_to_json::<u64, _>(
            &bench_id_unpack,
            (comp_param, param),
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
    use crate::utilities::cuda_num_streams;
    use std::cmp::max;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::gen_keys_radix_gpu;
    use tfhe::shortint::parameters::current_params::*;
    use tfhe::GpuIndex;

    fn gpu_glwe_packing(c: &mut Criterion) {
        let bench_name = "integer::cuda::packing_compression";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let stream = CudaStreams::new_multi_gpu();

        let param = V1_0_PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let comp_param = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

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
            comp_param.lwe_per_glwe.0 * log_message_modulus,
        ] {
            assert_eq!(bit_size % log_message_modulus, 0);
            let num_blocks = bit_size / log_message_modulus;

            let bench_id_pack;
            let bench_id_unpack;

            // Generate and convert compression keys
            let (radix_cks, _) = gen_keys_radix_gpu(param, num_blocks, &stream);
            let (compressed_compression_key, compressed_decompression_key) =
                radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);
            let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&stream);
            let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
                radix_cks.parameters().glwe_dimension(),
                radix_cks.parameters().polynomial_size(),
                radix_cks.parameters().message_modulus(),
                radix_cks.parameters().carry_modulus(),
                radix_cks.parameters().ciphertext_modulus(),
                &stream,
            );

            match BENCH_TYPE.get().unwrap() {
                BenchmarkType::Latency => {
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
                    let ct = cks.encrypt_radix(0_u32, num_blocks);
                    let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);

                    // Benchmark
                    let mut builder = CudaCompressedCiphertextListBuilder::new();

                    builder.push(d_ct, &stream);

                    let builders = (0..elements)
                        .map(|_| {
                            let ct = cks.encrypt_radix(0_u32, num_blocks);
                            let d_ct =
                                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &stream);
                            let mut builder = CudaCompressedCiphertextListBuilder::new();
                            builder.push(d_ct, &stream);

                            builder
                        })
                        .collect::<Vec<_>>();

                    let local_streams = (0..cuda_num_streams(num_block))
                        .map(|i| {
                            CudaStreams::new_single_gpu(GpuIndex::new(
                                (i % get_number_of_gpus() as u64) as u32,
                            ))
                        })
                        .cycle()
                        .take(elements as usize)
                        .collect::<Vec<_>>();

                    bench_id_pack = format!("{bench_name}::throughput::pack_u{bit_size}");
                    bench_group.bench_function(&bench_id_pack, |b| {
                        b.iter(|| {
                            builders.par_iter().zip(local_streams.par_iter()).for_each(
                                |(builder, local_stream)| {
                                    builder.build(&cuda_compression_key, local_stream);
                                },
                            )
                        })
                    });

                    let compressed = builders
                        .iter()
                        .map(|builder| builder.build(&cuda_compression_key, &stream))
                        .collect::<Vec<_>>();

                    bench_id_unpack = format!("{bench_name}::throughput::unpack_u{bit_size}");
                    bench_group.bench_function(&bench_id_unpack, |b| {
                        b.iter(|| {
                            compressed
                                .par_iter()
                                .zip(local_streams.par_iter())
                                .for_each(|(comp, local_stream)| {
                                    comp.get::<CudaUnsignedRadixCiphertext>(
                                        0,
                                        &cuda_decompression_key,
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
                (comp_param, param),
                comp_param.name(),
                "pack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );

            write_to_json::<u64, _>(
                &bench_id_unpack,
                (comp_param, param),
                comp_param.name(),
                "unpack",
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus.0.ilog2(); num_blocks],
            );
        }

        bench_group.finish()
    }

    criterion_group!(gpu_glwe_packing2, gpu_glwe_packing);
}

criterion_group!(cpu_glwe_packing2, cpu_glwe_packing);

#[cfg(feature = "gpu")]
use cuda::gpu_glwe_packing2;
use tfhe::{get_pbs_count, reset_pbs_count};

fn main() {
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap());

    #[cfg(feature = "gpu")]
    gpu_glwe_packing2();
    #[cfg(not(feature = "gpu"))]
    cpu_glwe_packing2();

    Criterion::default().configure_from_args().final_summary();
}
