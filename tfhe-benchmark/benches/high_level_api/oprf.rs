use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::tfhe::hlapi::oprf::OprfKind;
use benchmark_spec::{get_bench_type, BenchmarkSpec, BenchmarkType, HlapiBench, OperandType};
use criterion::{black_box, criterion_group, Criterion, Throughput};
use rayon::prelude::*;
#[cfg(any(feature = "gpu", feature = "hpu"))]
use std::cmp::max;
use std::num::NonZeroU64;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::ReRandomizationParameters;
#[cfg(any(feature = "gpu", feature = "hpu"))]
use tfhe::{get_pbs_count, reset_pbs_count};
use tfhe::{
    set_server_key, ClientKey, ConfigBuilder, FheUint64, RangeForRandom, ReRandomizationHashAlgo,
    ReRandomizationMode, Seed, ServerKey,
};

const OPRF_OUTPUT_BIT_SIZE: u32 = 64;

fn oprf_output_num_blocks(cks: &ClientKey) -> usize {
    let param = cks.computation_parameters();
    (OPRF_OUTPUT_BIT_SIZE as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize
}

fn oprf_throughput_elements<F>(cks: &ClientKey, run_op: F) -> u64
where
    F: Fn(),
{
    let num_blocks = oprf_output_num_blocks(cks);

    #[cfg(any(feature = "gpu", feature = "hpu"))]
    {
        use benchmark::utilities::throughput_num_threads;
        reset_pbs_count();
        run_op();
        let pbs_count = max(get_pbs_count(), 1);
        throughput_num_threads(num_blocks, pbs_count)
    }
    #[cfg(not(any(feature = "gpu", feature = "hpu")))]
    {
        use benchmark::find_optimal_batch::find_optimal_batch;
        let setup = |_batch_size: usize| ();
        let run = |_: &mut (), batch_size: usize| {
            (0..batch_size).into_par_iter().for_each(|_| {
                run_op();
            });
        };
        find_optimal_batch(run, setup) as u64
    }
}

fn oprf_any_range_bench(c: &mut Criterion, cks: &ClientKey) {
    let mut bench_group = c.benchmark_group("oprf");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let hlapi_op = HlapiBench::Oprf(OprfKind::AnyRange);
    let param = cks.computation_parameters();
    let param_name = param.name();
    let bench_type = get_bench_type();

    for excluded_upper_bound in [3, 52] {
        let bound_type = format!("bound_{excluded_upper_bound}",);
        let benchmark_spec = BenchmarkSpec::new_hlapi(
            hlapi_op,
            &param_name,
            OperandType::CipherText,
            Some(bound_type.as_str()),
            *bench_type,
            None,
        );
        let bench_id = benchmark_spec.to_string();

        let range = RangeForRandom::new_from_excluded_upper_bound(
            NonZeroU64::new(excluded_upper_bound).unwrap(),
        );

        match bench_type {
            BenchmarkType::Latency => {
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        _ = black_box(FheUint64::generate_oblivious_pseudo_random_custom_range(
                            Seed(0),
                            &range,
                            None,
                        ));
                    })
                });
            }
            BenchmarkType::Throughput => {
                let elements = oprf_throughput_elements(cks, || {
                    _ = FheUint64::generate_oblivious_pseudo_random_custom_range(
                        Seed(0),
                        &range,
                        None,
                    );
                });
                bench_group.throughput(Throughput::Elements(elements));

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            _ = black_box(
                                FheUint64::generate_oblivious_pseudo_random_custom_range(
                                    Seed(0),
                                    &range,
                                    None,
                                ),
                            );
                        })
                    })
                });
            }
        }

        write_to_json(
            &benchmark_spec,
            hlapi_op.to_string(),
            &OperatorType::Atomic,
            OPRF_OUTPUT_BIT_SIZE,
            vec![],
        );
    }

    bench_group.finish()
}

/// Benchmarks the custom-range PRF fused with re-randomization of the output blocks.
///
/// Requires a server key configured with re-randomization support (see the `_cpu`/`_gpu` entry
/// points). Uses the derived-CPK (no key-switch) mode, which is the configuration the GPU fused
/// kernel exercises by default.
fn oprf_any_range_rerand_bench(c: &mut Criterion, cks: &ClientKey) {
    let mut bench_group = c.benchmark_group("oprf");
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(30));

    let hlapi_op = HlapiBench::Oprf(OprfKind::AnyRangeRerand);
    let param = cks.computation_parameters();
    let param_name = param.name();
    let bench_type = get_bench_type();

    for excluded_upper_bound in [3, 52] {
        let bound_type = format!("bound_{excluded_upper_bound}",);
        let benchmark_spec = BenchmarkSpec::new_hlapi(
            hlapi_op,
            &param_name,
            OperandType::CipherText,
            Some(bound_type.as_str()),
            *bench_type,
            None,
        );
        let bench_id = benchmark_spec.to_string();

        let range = RangeForRandom::new_from_excluded_upper_bound(
            NonZeroU64::new(excluded_upper_bound).unwrap(),
        );

        match bench_type {
            BenchmarkType::Latency => {
                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        _ = black_box(
                            FheUint64::generate_oblivious_pseudo_random_custom_range_and_re_randomize(
                                Seed(0),
                                &range,
                                None,
                                ReRandomizationMode::UseAvailableMode,
                                ReRandomizationHashAlgo::Blake3,
                            ),
                        );
                    })
                });
            }
            BenchmarkType::Throughput => {
                let elements = oprf_throughput_elements(cks, || {
                    _ = FheUint64::generate_oblivious_pseudo_random_custom_range_and_re_randomize(
                        Seed(0),
                        &range,
                        None,
                        ReRandomizationMode::UseAvailableMode,
                        ReRandomizationHashAlgo::Blake3,
                    )
                    .unwrap();
                });
                bench_group.throughput(Throughput::Elements(elements));

                bench_group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        (0..elements).into_par_iter().for_each(|_| {
                            _ = black_box(
                                FheUint64::generate_oblivious_pseudo_random_custom_range_and_re_randomize(
                                    Seed(0),
                                    &range,
                                    None,
                                    ReRandomizationMode::UseAvailableMode,
                                    ReRandomizationHashAlgo::Blake3,
                                )
                                .unwrap(),
                            );
                        })
                    })
                });
            }
        }

        write_to_json(
            &benchmark_spec,
            hlapi_op.to_string(),
            &OperatorType::Atomic,
            OPRF_OUTPUT_BIT_SIZE,
            vec![],
        );
    }

    bench_group.finish()
}

pub fn oprf_any_range_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    oprf_any_range_bench(c, &cks);
}

#[cfg(feature = "gpu")]
pub fn oprf_any_range_gpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = tfhe::CompressedServerKey::new(&cks).decompress_to_gpu();

    set_server_key(sks);

    oprf_any_range_bench(c, &cks);
}

pub fn oprf_any_range_rerand_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param)
        .use_dedicated_oprf_key(true)
        .enable_ciphertext_re_randomization(ReRandomizationParameters::DerivedCPKWithoutKeySwitch)
        .build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    oprf_any_range_rerand_bench(c, &cks);
}

#[cfg(feature = "gpu")]
pub fn oprf_any_range_rerand_gpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param)
        .use_dedicated_oprf_key(true)
        .enable_ciphertext_re_randomization(ReRandomizationParameters::DerivedCPKWithoutKeySwitch)
        .build();
    let cks = ClientKey::generate(config);
    let sks = tfhe::CompressedServerKey::new(&cks).decompress_to_gpu();

    set_server_key(sks);

    oprf_any_range_rerand_bench(c, &cks);
}

#[cfg(not(feature = "gpu"))]
criterion_group!(
    oprf_any_range2,
    oprf_any_range_cpu,
    oprf_any_range_rerand_cpu
);

#[cfg(feature = "gpu")]
criterion_group!(
    oprf_any_range2,
    oprf_any_range_cpu,
    oprf_any_range_gpu,
    oprf_any_range_rerand_cpu,
    oprf_any_range_rerand_gpu
);
