use benchmark::params::ParamsAndNumBlocksIter;
#[cfg(any(feature = "gpu", feature = "hpu"))]
use benchmark::utilities::throughput_num_threads;
use benchmark::utilities::{write_to_json_unchecked, OperatorType};
use benchmark_spec::{get_bench_type, BenchmarkType};
use criterion::{black_box, Criterion, Throughput};
use rayon::prelude::*;
#[cfg(any(feature = "gpu", feature = "hpu"))]
use std::cmp::max;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::oprf::{OprfPrivateKey, OprfServerKey};
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;
#[cfg(any(feature = "gpu", feature = "hpu"))]
use tfhe::{get_pbs_count, reset_pbs_count};
use tfhe_csprng::seeders::Seed;

pub fn unsigned_oprf(c: &mut Criterion) {
    let bench_name = "integer::unsigned_oprf";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let param_name = param.name();

        let bench_id_oprf;
        let bench_id_oprf_bounded;

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id_oprf = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_id_oprf_bounded =
                    format!("{bench_name}_bounded::{param_name}::{bit_size}_bits");

                bench_group.bench_function(&bench_id_oprf, |b| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let oprf_pk = OprfPrivateKey::new(&cks);
                    let oprf_sk = OprfServerKey::new(&oprf_pk, &cks).unwrap();

                    b.iter(|| {
                        _ = black_box(
                            oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                                Seed(0),
                                num_block as u64,
                                &sks,
                            ),
                        );
                    })
                });

                bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let oprf_pk = OprfPrivateKey::new(&cks);
                    let oprf_sk = OprfServerKey::new(&oprf_pk, &cks).unwrap();

                    b.iter(|| {
                        _ = black_box(
                            oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                Seed(0),
                                bit_size as u64,
                                num_block as u64,
                                &sks,
                            ),
                        );
                    })
                });
            }
            BenchmarkType::Throughput => {
                let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                let oprf_pk = OprfPrivateKey::new(&cks);
                let oprf_sk = OprfServerKey::new(&oprf_pk, &cks).unwrap();

                bench_id_oprf = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_id_oprf_bounded =
                    format!("{bench_name}_bounded::throughput::{param_name}::{bit_size}_bits");

                let elements = {
                    #[cfg(any(feature = "gpu", feature = "hpu"))]
                    {
                        // Execute the operation once to know its cost.
                        reset_pbs_count();
                        oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                            Seed(0),
                            bit_size as u64,
                            num_block as u64,
                            &sks,
                        );
                        let pbs_count = max(get_pbs_count(), 1);
                        throughput_num_threads(num_block, pbs_count)
                    }
                    #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                    {
                        use benchmark::find_optimal_batch::find_optimal_batch;
                        let setup = |_batch_size: usize| ();
                        let run = |_: &mut (), batch_size: usize| {
                            (0..batch_size).into_par_iter().for_each(|_| {
                                oprf_sk
                                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                        Seed(0),
                                        bit_size as u64,
                                        num_block as u64,
                                        &sks,
                                    );
                            });
                        };
                        find_optimal_batch(run, setup) as u64
                    }
                };
                bench_group.throughput(Throughput::Elements(elements));

                bench_group.bench_function(&bench_id_oprf, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                                Seed(0),
                                num_block as u64,
                                &sks,
                            );
                        })
                    })
                });

                bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                Seed(0),
                                bit_size as u64,
                                num_block as u64,
                                &sks,
                            );
                        })
                    })
                });
            }
        }

        for (bench_id, display_name) in [
            (bench_id_oprf, "oprf"),
            (bench_id_oprf_bounded, "oprf_bounded"),
        ] {
            write_to_json_unchecked::<u64, _>(
                &bench_id,
                param,
                param.name(),
                display_name,
                &OperatorType::Atomic,
                bit_size as u32,
                vec![param.message_modulus().0.ilog2(); num_block],
            );
        }
    }

    bench_group.finish()
}

#[cfg(feature = "gpu")]
pub mod cuda {
    use super::*;
    use benchmark::utilities::cuda_integer_utils::cuda_local_keys;
    use criterion::black_box;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::server_key::CudaServerKey;
    use tfhe::integer::gpu::CudaOprfServerKey;
    use tfhe::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    use tfhe::GpuIndex;
    use tfhe_csprng::seeders::Seed;

    pub fn cuda_unsigned_oprf(c: &mut Criterion) {
        let bench_name = "integer::cuda::unsigned_oprf";

        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(30));

        for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
            let param_name = param.name();

            let bench_id_oprf;
            let bench_id_oprf_bounded;

            match get_bench_type() {
                BenchmarkType::Latency => {
                    let streams = CudaStreams::new_multi_gpu();

                    bench_id_oprf = format!("{bench_name}::{param_name}::{bit_size}_bits");
                    bench_id_oprf_bounded =
                        format!("{bench_name}_bounded::{param_name}::{bit_size}_bits");

                    bench_group.bench_function(&bench_id_oprf, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);
                        let oprf_pk = OprfPrivateKey::new(&cks);
                        let compressed_oprf_sk =
                            CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
                        let cuda_oprf_sk =
                            CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);

                        b.iter(|| {
                            _ = black_box(
                                cuda_oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                                    Seed(0),
                                    num_block as u64,
                                    &gpu_sks,
                                    &streams,
                                ),
                            );
                        })
                    });

                    bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);
                        let oprf_pk = OprfPrivateKey::new(&cks);
                        let compressed_oprf_sk =
                            CompressedOprfServerKey::new(&oprf_pk, &cks).unwrap();
                        let cuda_oprf_sk =
                            CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &streams);

                        b.iter(|| {
                            _ = black_box(
                                cuda_oprf_sk
                                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                        Seed(0),
                                        bit_size as u64,
                                        num_block as u64,
                                        &gpu_sks,
                                        &streams,
                                    ),
                            );
                        })
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_sks_vec = cuda_local_keys(&cks);
                    let cpu_oprf_pk = OprfPrivateKey::new(&cks);
                    let cpu_oprf_sk = OprfServerKey::new(&cpu_oprf_pk, &cks).unwrap();
                    let compressed_oprf_sk =
                        CompressedOprfServerKey::new(&cpu_oprf_pk, &cks).unwrap();
                    // One CudaOprfServerKey per GPU, matching `gpu_sks_vec`.
                    let cuda_oprf_sks_vec: Vec<CudaOprfServerKey> = (0..get_number_of_gpus())
                        .map(|gpu_index| {
                            let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
                            CudaOprfServerKey::decompress_from_cpu(&compressed_oprf_sk, &stream)
                        })
                        .collect();

                    // Execute the operation once to know its cost.
                    reset_pbs_count();
                    cpu_oprf_sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        Seed(0),
                        bit_size as u64,
                        num_block as u64,
                        &cpu_sks,
                    );
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id_oprf =
                        format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_id_oprf_bounded =
                        format!("{bench_name}_bounded::throughput::{param_name}::{bit_size}_bits");
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));

                    bench_group.bench_function(&bench_id_oprf, |b| {
                        b.iter(|| {
                            (0..elements).into_par_iter().for_each(|i| {
                                let gpu_index: u32 = i as u32 % get_number_of_gpus();
                                let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
                                cuda_oprf_sks_vec[gpu_index as usize]
                                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                                        Seed(0),
                                        num_block as u64,
                                        &gpu_sks_vec[gpu_index as usize],
                                        &stream,
                                    );
                            })
                        })
                    });

                    bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                        b.iter(|| {
                            (0..elements).into_par_iter().for_each(|i| {
                                let gpu_index: u32 = i as u32 % get_number_of_gpus();
                                let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
                                cuda_oprf_sks_vec[gpu_index as usize]
                                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                        Seed(0),
                                        bit_size as u64,
                                        num_block as u64,
                                        &gpu_sks_vec[gpu_index as usize],
                                        &stream,
                                    );
                            })
                        })
                    });
                }
            }

            for (bench_id, display_name) in [
                (bench_id_oprf, "oprf"),
                (bench_id_oprf_bounded, "oprf_bounded"),
            ] {
                write_to_json_unchecked::<u64, _>(
                    &bench_id,
                    param,
                    param.name(),
                    display_name,
                    &OperatorType::Atomic,
                    bit_size as u32,
                    vec![param.message_modulus().0.ilog2(); num_block],
                );
            }
        }

        bench_group.finish()
    }
}
