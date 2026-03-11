use benchmark::params_aliases::{
    BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1,
};
use benchmark::utilities::{get_bench_type, write_to_json, BenchmarkType, OperatorType};
use criterion::{black_box, criterion_group, BatchSize, Criterion, Throughput};
#[cfg(feature = "gpu")]
use cuda::gpu_re_randomize_group;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::prelude::{IntoParallelIterator, IntoParallelRefMutIterator};
use tfhe::integer::ciphertext::{
    CompressedCiphertextListBuilder, ReRandomizationContext, ReRandomizationKey,
};
use tfhe::integer::key_switching_key::{KeySwitchingKey, KeySwitchingKeyMaterial};
use tfhe::integer::{gen_keys_radix, CompactPrivateKey, CompactPublicKey, RadixCiphertext};
use tfhe::keycache::NamedParam;

enum BenchReRandomizeMode {
    LegacyWithKeyswitch,
    NoKeyswitch,
}

impl std::fmt::Display for BenchReRandomizeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchReRandomizeMode::LegacyWithKeyswitch => f.write_str("legacykeyswitch"),
            BenchReRandomizeMode::NoKeyswitch => f.write_str("nokeyswitch"),
        }
    }
}

fn execute_cpu_re_randomize(c: &mut Criterion, bit_size: usize, rerand_mode: BenchReRandomizeMode) {
    let bench_name = format!("integer::re_randomize_{rerand_mode}");
    let bench_name = &bench_name;
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

    let cpk;
    let ksk_material;
    let re_randomization_key = match rerand_mode {
        BenchReRandomizeMode::LegacyWithKeyswitch => {
            let compact_private_key = CompactPrivateKey::new(cpk_param);
            cpk = CompactPublicKey::new(&compact_private_key);

            let (shortint_ksk_material, _, _) =
                KeySwitchingKey::new((&compact_private_key, None), ((&cks), (&sks)), ks_param)
                    .into_raw_parts()
                    .into_raw_parts();
            ksk_material = KeySwitchingKeyMaterial::from_raw_parts(shortint_ksk_material);
            ReRandomizationKey::LegacyDedicatedCPK {
                cpk: &cpk,
                ksk: ksk_material.as_view(),
            }
        }
        BenchReRandomizeMode::NoKeyswitch => {
            let compact_private_key: CompactPrivateKey<&[u64]> = cks.try_into().unwrap();
            cpk = CompactPublicKey::new(&compact_private_key);
            ReRandomizationKey::DerivedCPKWithoutKeySwitch { cpk: &cpk }
        }
    };

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
                            .re_randomize(re_randomization_key, seed_gen.next_seed().unwrap())
                            .unwrap();

                        _ = black_box(&d_re_randomized);
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        BenchmarkType::Throughput => {
            let setup = |batch_size: usize| {
                (0..batch_size)
                    .into_par_iter()
                    .map(|_| {
                        let message = 42u64;
                        let ct = cks.encrypt_radix(message, num_blocks);

                        let mut builder = CompressedCiphertextListBuilder::new();
                        builder.push(ct);
                        let compressed = builder.build(&compression_key);

                        compressed.get(0, &decompression_key).unwrap().unwrap()
                    })
                    .collect::<Vec<RadixCiphertext>>()
            };
            let generate_seeds = |cts: &[RadixCiphertext]| {
                let mut ctx = ReRandomizationContext::new(
                    rerand_domain_separator,
                    [metadata],
                    compact_public_encryption_domain_separator,
                );
                for ct in cts {
                    ctx.add_ciphertext(ct);
                }
                let mut seed_gen = ctx.finalize();
                (0..cts.len())
                    .map(|_| seed_gen.next_seed().unwrap())
                    .collect::<Vec<_>>()
            };
            let run = |cts: &mut Vec<RadixCiphertext>, seeds: Vec<_>| {
                cts.par_iter_mut().zip(seeds.into_par_iter()).for_each(
                    |(d_re_randomized, seed)| {
                        d_re_randomized
                            .re_randomize(re_randomization_key, seed)
                            .unwrap();

                        _ = black_box(&d_re_randomized);
                    },
                );
            };
            let elements = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    throughput_num_threads(num_blocks, 1)
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::find_optimal_batch::find_optimal_batch;
                    find_optimal_batch(
                        |cts, _batch_size| {
                            let seeds = generate_seeds(cts);
                            run(cts, seeds);
                        },
                        &setup,
                    ) as u64
                }
            };
            bench_group.throughput(Throughput::Elements(elements));

            bench_id = format!("{bench_name}::throughput_u{bit_size}");
            bench_group.bench_function(&bench_id, |b| {
                b.iter_batched(
                    || {
                        let cts = setup(elements as usize);
                        let seeds = generate_seeds(&cts);
                        (cts, seeds)
                    },
                    |(mut cts, seeds)| run(&mut cts, seeds),
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
        execute_cpu_re_randomize(c, *bit_size, BenchReRandomizeMode::LegacyWithKeyswitch);
        execute_cpu_re_randomize(c, *bit_size, BenchReRandomizeMode::NoKeyswitch);
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
    use tfhe::integer::gpu::ciphertext::re_randomization::CudaReRandomizationKey;
    use tfhe::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
    use tfhe::integer::gpu::key_switching_key::CudaKeySwitchingKeyMaterial;
    use tfhe::integer::key_switching_key::KeySwitchingKey;
    use tfhe::integer::{gen_keys_radix, CompactPrivateKey, CompactPublicKey};
    use tfhe::keycache::NamedParam;

    fn execute_gpu_re_randomize(
        c: &mut Criterion,
        bit_size: usize,
        rerand_mode: super::BenchReRandomizeMode,
    ) {
        let bench_name = format!("integer::cuda::re_randomize_{rerand_mode}");
        let bench_name = &bench_name;
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
        let comp_param = BENCH_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let streams = CudaStreams::new_multi_gpu();

        let num_blocks =
            (bit_size as f64 / (param.message_modulus.0 as f64).log(2.0)).ceil() as usize;

        let (radix_cks, sks) = gen_keys_radix(param, num_blocks);
        let cks = radix_cks.as_ref();

        let private_compression_key = cks.new_compression_private_key(comp_param);
        let (cuda_compression_key, cuda_decompression_key) =
            radix_cks.new_cuda_compression_decompression_keys(&private_compression_key, &streams);

        // Build the CPK and (optionally) KSK depending on the mode.
        // `ksk` and `d_ksk_material` are `Option` because they only exist in the legacy mode,
        // but must outlive `re_randomization_key` which borrows from them.
        let cpk;
        let ksk;
        let d_ksk_material;
        // The `NoKeyswitch` branch assigns `d_ksk_material = None` which is never read, but
        // the variable must be initialized in all branches so it can be dropped at scope end.
        #[allow(unused_assignments)]
        let re_randomization_key = match rerand_mode {
            super::BenchReRandomizeMode::LegacyWithKeyswitch => {
                let cpk_param = BENCH_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV1;
                let ks_param =
                    BENCH_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

                let cpk_private_key = CompactPrivateKey::new(cpk_param);
                cpk = CompactPublicKey::new(&cpk_private_key);
                ksk = Some(KeySwitchingKey::new(
                    (&cpk_private_key, None),
                    (&cks, &sks),
                    ks_param,
                ));
                d_ksk_material = Some(CudaKeySwitchingKeyMaterial::from_key_switching_key(
                    ksk.as_ref().unwrap(),
                    &streams,
                ));
                CudaReRandomizationKey::LegacyDedicatedCPK {
                    cpk: &cpk,
                    ksk: d_ksk_material.as_ref().unwrap(),
                }
            }
            super::BenchReRandomizeMode::NoKeyswitch => {
                let compact_private_key: CompactPrivateKey<&[u64]> = cks.try_into().unwrap();
                cpk = CompactPublicKey::new(&compact_private_key);
                ksk = None;
                d_ksk_material = None;
                CudaReRandomizationKey::DerivedCPKWithoutKeySwitch { cpk: &cpk }
            }
        };

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
                                    re_randomization_key,
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

                // Only create per-GPU KSK copies for the legacy mode
                let d_ksk_material_vec: Option<Vec<CudaKeySwitchingKeyMaterial>> =
                    ksk.as_ref().map(|ksk| {
                        (0..num_gpus)
                            .map(|i| {
                                let local_stream = &local_streams[i % local_streams.len()];
                                CudaKeySwitchingKeyMaterial::from_key_switching_key(
                                    ksk,
                                    local_stream,
                                )
                            })
                            .collect()
                    });

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
                            let num_cts = h_decompressed_cts.len();
                            (ctx.finalize(), num_cts, d_cts_to_rerand)
                        },
                        |(mut seed_gen, num_cts, mut d_cts_to_rerand)| {
                            let seeds: Vec<_> = (0..num_cts)
                                .map(|_| seed_gen.next_seed().unwrap())
                                .collect();

                            d_cts_to_rerand
                                .par_iter_mut()
                                .zip(seeds.into_par_iter())
                                .enumerate()
                                .for_each(|(i, (d_re_randomized, seed))| {
                                    let local_stream = &local_streams[i % local_streams.len()];

                                    let re_randomization_key = match &d_ksk_material_vec {
                                        Some(vec) => CudaReRandomizationKey::LegacyDedicatedCPK {
                                            cpk: &cpk,
                                            ksk: &vec[i % num_gpus],
                                        },
                                        None => {
                                            CudaReRandomizationKey::DerivedCPKWithoutKeySwitch {
                                                cpk: &cpk,
                                            }
                                        }
                                    };

                                    d_re_randomized
                                        .re_randomize(re_randomization_key, seed, local_stream)
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
        use super::BenchReRandomizeMode;

        let bit_sizes = [2, 4, 16, 32, 64, 128, 256];

        for bit_size in bit_sizes.iter() {
            execute_gpu_re_randomize(c, *bit_size, BenchReRandomizeMode::LegacyWithKeyswitch);
            execute_gpu_re_randomize(c, *bit_size, BenchReRandomizeMode::NoKeyswitch);
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
