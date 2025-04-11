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

        let bench_id;

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{param_name}::{bit_size}_bits");
                bench_group.bench_function(&bench_id, |b| {
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

                bench_id = format!("{bench_name}::throughput::{param_name}::{bit_size}_bits");
                let elements = throughput_num_threads(num_block, pbs_count);
                bench_group.throughput(Throughput::Elements(elements));
                bench_group.bench_function(&bench_id, |b| {
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

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            "oprf",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block],
        );
    }

    bench_group.finish()
}
