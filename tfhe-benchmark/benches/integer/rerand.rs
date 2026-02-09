use benchmark::params_aliases::{
    BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
};
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{black_box, criterion_group, BatchSize, Criterion, Throughput};
#[cfg(feature = "gpu")]
use cuda::gpu_re_randomize_group;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::prelude::{IntoParallelIterator, IntoParallelRefMutIterator};
use tfhe::integer::ciphertext::{CompressedCiphertextListBuilder, ReRandomizationContext};
use tfhe::integer::key_switching_key::{KeySwitchingKey, KeySwitchingKeyMaterial};
use tfhe::integer::{gen_keys_radix, CompactPrivateKey, CompactPublicKey, RadixCiphertext};
use tfhe::keycache::NamedParam;

fn execute_cpu_re_randomize(c: &mut Criterion, bit_size: usize) {
    let bench_name = "integer::re_randomize";
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let cpk_param = BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;
    let ks_param = BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let num_blocks = (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

    let (radix_cks, sks) = gen_keys_radix(param, num_blocks);
    let cks = radix_cks.as_ref();

    let private_compression_key = cks.new_compression_private_key(comp_param);
    let (compressed_compression_key, compressed_decompression_key) =
        radix_cks.new_compressed_compression_decompression_keys(&private_compression_key);

    let compression_key = compressed_compression_key.decompress();
    let decompression_key = compressed_decompression_key.decompress();

    let cpk_private_key = CompactPrivateKey::new(cpk_param);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let ksk = KeySwitchingKey::new((&cpk_private_key, None), ((&cks), (&sks)), ks_param);
    let ksk = ksk.into_raw_parts();
    let (ksk_material, _, _) = ksk.into_raw_parts();
    let ksk_material = KeySwitchingKeyMaterial::from_raw_parts(ksk_material);

    let rerand_domain_separator = *b"TFHE_Rrd";
    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let metadata = b"bench".as_slice();

    let bench_id;

    match get_bench_type() {
        BenchmarkType::Latency => {
            // Encrypt and compress a single ciphertext
            let message = 42u64;
            let ct = cks.encrypt_radix(message, num_blocks);

            let mut builder = CompressedCiphertextListBuilder::new();
            builder.push(ct);
            let compressed = builder.build(&compression_key);
            let decompressed: RadixCiphertext =
                compressed.get(0, &decompression_key).unwrap().unwrap();

            let mut d_re_randomized = decompressed.clone();

            bench_id = format!("{bench_name}::latency_u{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || {
                        let mut re_randomizer_context = ReRandomizationContext::new(
                            rerand_domain_separator,
                            [metadata],
                            compact_public_encryption_domain_separator,
                        );

                        re_randomizer_context.add_ciphertext(&decompressed);
                        re_randomizer_context.finalize()
                    },
                    |mut seed_gen| {
                        d_re_randomized
                            .re_randomize(
                                &cpk,
                                &ksk_material.as_view(),
                                seed_gen.next_seed().unwrap(),
                            )
                            .unwrap();

                        _ = black_box(&d_re_randomized);
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        BenchmarkType::Throughput => {
            let elements = throughput_num_threads(num_blocks, 1);
            bench_group.throughput(Throughput::Elements(elements));

            // Pre-generate and compress ciphertexts for throughput test
            let decompressed_cts: Vec<RadixCiphertext> = (0..elements as usize)
                .into_par_iter()
                .map(|_| {
                    let message = 42u64;
                    let ct = cks.encrypt_radix(message, num_blocks);

                    let mut builder = CompressedCiphertextListBuilder::new();
                    builder.push(ct);
                    let compressed = builder.build(&compression_key);

                    compressed.get(0, &decompression_key).unwrap().unwrap()
                })
                .collect();

            bench_id = format!("{bench_name}::throughput_u{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || {
                        // Create a fresh context for each benchmark iteration
                        let mut ctx = ReRandomizationContext::new(
                            rerand_domain_separator,
                            [metadata],
                            compact_public_encryption_domain_separator,
                        );

                        // Add all ciphertexts to the context
                        for ct in &decompressed_cts {
                            ctx.add_ciphertext(ct);
                        }

                        // Return a new seed generator for this iteration
                        (ctx.finalize(), decompressed_cts.clone())
                    },
                    |(mut seed_gen, mut cts_to_rerand)| {
                        let seeds: Vec<_> = (0..cts_to_rerand.len())
                            .map(|_| seed_gen.next_seed().unwrap())
                            .collect();

                        cts_to_rerand
                            .par_iter_mut()
                            .zip(seeds.into_par_iter())
                            .for_each(|(d_re_randomized, seed)| {
                                d_re_randomized
                                    .re_randomize(&cpk, &ksk_material.as_view(), seed)
                                    .unwrap();

                                _ = black_box(&d_re_randomized);
                            })
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    write_to_json::<u64, _>(
        &bench_id,
        (comp_param, param.into()),
        comp_param.name(),
        "re_randomize",
        &OperatorType::Atomic,
        bit_size as u32,
        vec![param.message_modulus.0.ilog2(); num_blocks],
    );

    bench_group.finish()
}

fn cpu_re_randomize(c: &mut Criterion) {
    let bit_sizes = [2, 4, 8, 16, 32, 64, 128, 256];

    for bit_size in bit_sizes.iter() {
        execute_cpu_re_randomize(c, *bit_size);
    }
}

criterion_group!(cpu_re_randomize_group, cpu_re_randomize);

#[cfg(feature = "gpu")]
mod cuda {
    use benchmark::params_aliases::{
        BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
    };
    use benchmark::utilities::cuda_integer_utils::cuda_local_streams;
    use benchmark::utilities::{
        get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
    };
    use criterion::{black_box, criterion_group, BatchSize, Criterion, Throughput};
    use rayon::prelude::*;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::ciphertext::ReRandomizationContext;
    use tfhe::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
    use tfhe::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
    use tfhe::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
    use tfhe::integer::key_switching_key::KeySwitchingKey;
    use tfhe::integer::{gen_keys_radix, CompactPrivateKey, CompactPublicKey};
    use tfhe::keycache::NamedParam;

    fn execute_gpu_re_randomize(c: &mut Criterion, bit_size: usize) {
        let bench_name = "integer::cuda::re_randomize";
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
        let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_param = BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;
        let ks_param = BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let streams = CudaStreams::new_multi_gpu();

        let num_blocks =
            (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        let (radix_cks, sks) = gen_keys_radix(param, num_blocks);
        let cks = radix_cks.as_ref();

        let private_compression_key = cks.new_compression_private_key(comp_param);
        let (cuda_compression_key, cuda_decompression_key) =
            radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

        let cpk_private_key = CompactPrivateKey::new(cpk_param);
        let cpk = CompactPublicKey::new(&cpk_private_key);
        let ksk = KeySwitchingKey::new((&cpk_private_key, None), (&cks, &sks), ks_param);
        let d_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);

        let rerand_domain_separator = *b"TFHE_Rrd";
        let compact_public_encryption_domain_separator = *b"TFHE_Enc";
        let metadata = b"bench".as_slice();

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                // Encrypt and compress a single ciphertext
                let message = 42u64;
                let ct = cks.encrypt_radix(message, num_blocks);
                let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);

                let mut builder = CudaCompressedCiphertextListBuilder::new();
                builder.push(d_ct, &streams);
                let compressed = builder.build(&cuda_compression_key, &streams);
                let d_decompressed: CudaUnsignedRadixCiphertext = compressed
                    .get(0, &cuda_decompression_key, &streams)
                    .unwrap()
                    .unwrap();

                let decompressed = d_decompressed.to_radix_ciphertext(&streams);

                let mut d_re_randomized = d_decompressed.duplicate(&streams);

                bench_id = format!("{bench_name}::latency_u{bit_size}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter_batched(
                        || {
                            let mut re_randomizer_context = ReRandomizationContext::new(
                                rerand_domain_separator,
                                [metadata],
                                compact_public_encryption_domain_separator,
                            );

                            re_randomizer_context.add_ciphertext(&decompressed);
                            re_randomizer_context.finalize()
                        },
                        |mut seed_gen| {
                            d_re_randomized
                                .re_randomize(
                                    &cpk,
                                    &d_ksk_material,
                                    seed_gen.next_seed().unwrap(),
                                    &streams,
                                )
                                .unwrap();

                            _ = black_box(&d_re_randomized);
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
            BenchmarkType::Throughput => {
                let elements = throughput_num_threads(num_blocks, 1);
                bench_group.throughput(Throughput::Elements(elements));

                let local_streams = cuda_local_streams(num_blocks, elements as usize);
                let num_gpus = get_number_of_gpus() as usize;

                let d_ksk_material_vec: Vec<CudaKeySwitchingKeyMaterial> = (0..num_gpus)
                    .map(|i| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, local_stream)
                    })
                    .collect();

                // Pre-generate and compress ciphertexts for throughput test
                let d_compressed_cts: Vec<CudaUnsignedRadixCiphertext> = (0..elements as usize)
                    .into_par_iter()
                    .map(|i| {
                        let message = 42u64;
                        let ct = cks.encrypt_radix(message, num_blocks);
                        let local_stream = &local_streams[i % local_streams.len()];
                        let d_ct =
                            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, local_stream);

                        let mut builder = CudaCompressedCiphertextListBuilder::new();
                        builder.push(d_ct, local_stream);
                        let compressed = builder.build(&cuda_compression_key, local_stream);

                        compressed
                            .get(0, &cuda_decompression_key, local_stream)
                            .unwrap()
                            .unwrap()
                    })
                    .collect();

                // Prepare decompressed ciphertexts once
                let h_decompressed_cts: Vec<_> = d_compressed_cts
                    .iter()
                    .enumerate()
                    .map(|(i, d_ct)| {
                        let local_stream = &local_streams[i % local_streams.len()];
                        d_ct.to_radix_ciphertext(local_stream)
                    })
                    .collect();

                bench_id = format!("{bench_name}::throughput_u{bit_size}");
                bench_group.bench_function(&bench_id, |b| {
                    b.iter_batched(
                        || {
                            // Create a fresh context for each benchmark iteration
                            let mut ctx = ReRandomizationContext::new(
                                rerand_domain_separator,
                                [metadata],
                                compact_public_encryption_domain_separator,
                            );

                            // Add all ciphertexts to the context
                            for ct in &h_decompressed_cts {
                                ctx.add_ciphertext(ct);
                            }

                            let d_cts_to_rerand = d_compressed_cts
                                .iter()
                                .enumerate()
                                .map(|(i, d_ct)| {
                                    let local_stream = &local_streams[i % local_streams.len()];
                                    d_ct.duplicate(local_stream)
                                })
                                .collect::<Vec<_>>();

                            // Return a new seed generator for this iteration
                            (ctx.finalize(), h_decompressed_cts.clone(), d_cts_to_rerand)
                        },
                        |(mut seed_gen, h_cts_to_rerand, mut d_cts_to_rerand)| {
                            let seeds: Vec<_> = (0..h_cts_to_rerand.len())
                                .map(|_| seed_gen.next_seed().unwrap())
                                .collect();

                            d_cts_to_rerand
                                .par_iter_mut()
                                .zip(seeds.into_par_iter())
                                .enumerate()
                                .for_each(|(i, (d_re_randomized, seed))| {
                                    let local_stream = &local_streams[i % local_streams.len()];
                                    let d_ksk = &d_ksk_material_vec[i % num_gpus];

                                    d_re_randomized
                                        .re_randomize(&cpk, d_ksk, seed, local_stream)
                                        .unwrap();

                                    _ = black_box(&d_re_randomized);
                                })
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
        }

        write_to_json::<u64, _>(
            &bench_id,
            (comp_param, param.into()),
            comp_param.name(),
            "re_randomize",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus.0.ilog2(); num_blocks],
        );

        bench_group.finish()
    }

    fn gpu_re_randomize(c: &mut Criterion) {
        let bit_sizes = [2, 4, 16, 32, 64, 128, 256];

        for bit_size in bit_sizes.iter() {
            execute_gpu_re_randomize(c, *bit_size);
        }
    }

    criterion_group!(gpu_re_randomize_group, gpu_re_randomize);
}

fn main() {
    #[cfg(feature = "gpu")]
    gpu_re_randomize_group();
    #[cfg(not(feature = "gpu"))]
    cpu_re_randomize_group();
    Criterion::default().configure_from_args().final_summary();
}
