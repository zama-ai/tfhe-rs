use benchmark::params::ParamsAndNumBlocksIter;
use benchmark::utilities::{
    get_bench_type, throughput_num_threads, write_to_json, BenchmarkType, OperatorType,
};
use criterion::{black_box, Criterion, Throughput};
use rayon::prelude::*;
use std::cmp::max;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;
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

                println!("{bench_id_oprf}");
                bench_group.bench_function(&bench_id_oprf, |b| {
                    let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    b.iter(|| {
                        _ = black_box(sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                            Seed(0),
                            num_block as u64,
                        ));
                    })
                });

                println!("{bench_id_oprf_bounded}");
                bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                    let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                    b.iter(|| {
                        _ = black_box(
                            sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                Seed(0),
                                bit_size as u64,
                                num_block as u64,
                            ),
                        );
                    })
                });
            }
            BenchmarkType::Throughput => {
                let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

                // Execute the operation once to know its cost.
                reset_pbs_count();
                sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                    Seed(0),
                    bit_size as u64,
                    num_block as u64,
                );
                let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                bench_id_oprf = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                bench_id_oprf_bounded =
                    format!("{bench_name}_bounded::throughput::{param_name}::{bit_size}_bits");

                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));

                println!("{bench_id_oprf}");
                bench_group.bench_function(&bench_id_oprf, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                                Seed(0),
                                num_block as u64,
                            );
                        })
                    })
                });

                println!("{bench_id_oprf_bounded}");
                bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            sk.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                Seed(0),
                                bit_size as u64,
                                num_block as u64,
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
            write_to_json::<u64, _>(
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
    use std::cmp::max;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::integer::gpu::server_key::CudaServerKey;
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

                    println!("{bench_id_oprf}");
                    bench_group.bench_function(&bench_id_oprf, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);

                        b.iter(|| {
                            _ = black_box(
                                gpu_sks.par_generate_oblivious_pseudo_random_unsigned_integer(
                                    Seed(0),
                                    num_block as u64,
                                    &streams,
                                ),
                            );
                        })
                    });

                    println!("{bench_id_oprf_bounded}");
                    bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                        let (cks, _cpu_sks) =
                            KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                        let gpu_sks = CudaServerKey::new(&cks, &streams);

                        b.iter(|| {
                            _ = black_box(
                                gpu_sks
                                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                        Seed(0),
                                        bit_size as u64,
                                        num_block as u64,
                                        &streams,
                                    ),
                            );
                        })
                    });
                }
                BenchmarkType::Throughput => {
                    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
                    let gpu_sks_vec = cuda_local_keys(&cks);

                    // Execute the operation once to know its cost.
                    reset_pbs_count();
                    cpu_sks.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        Seed(0),
                        bit_size as u64,
                        num_block as u64,
                    );
                    let pbs_count = max(get_pbs_count(), 1); // Operation might not perform any PBS, so we take 1 as default

                    bench_id_oprf =
                        format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                    bench_id_oprf_bounded =
                        format!("{bench_name}_bounded::throughput::{param_name}::{bit_size}_bits");
                    let elements = throughput_num_threads(num_block, pbs_count);
                    bench_group.throughput(Throughput::Elements(elements));

                    println!("{bench_id_oprf}");
                    bench_group.bench_function(&bench_id_oprf, |b| {
                        b.iter(|| {
                            (0..elements).into_par_iter().for_each(|i| {
                                let gpu_index: u32 = i as u32 % get_number_of_gpus();
                                let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
                                gpu_sks_vec[gpu_index as usize]
                                    .par_generate_oblivious_pseudo_random_unsigned_integer(
                                        Seed(0),
                                        num_block as u64,
                                        &stream,
                                    );
                            })
                        })
                    });

                    println!("{bench_id_oprf_bounded}");
                    bench_group.bench_function(&bench_id_oprf_bounded, |b| {
                        b.iter(|| {
                            (0..elements).into_par_iter().for_each(|i| {
                                let gpu_index: u32 = i as u32 % get_number_of_gpus();
                                let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
                                gpu_sks_vec[gpu_index as usize]
                                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                                        Seed(0),
                                        bit_size as u64,
                                        num_block as u64,
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
                write_to_json::<u64, _>(
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
