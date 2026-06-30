#[cfg(not(any(feature = "gpu", feature = "hpu")))]
use benchmark::find_optimal_batch::find_optimal_batch;
#[cfg(feature = "gpu")]
use benchmark::params_aliases::{
    BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
#[cfg(feature = "gpu")]
use benchmark::utilities::{configure_gpu, get_param_type, ParamType};
use benchmark::utilities::{write_to_json_unchecked, BitSizesSet, EnvConfig, OperatorType};
use benchmark_spec::{get_bench_type, BenchmarkType};
use criterion::{Criterion, Throughput};
use rayon::prelude::*;
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
#[cfg(feature = "gpu")]
use tfhe::shortint::AtomicPatternParameters;
use tfhe::{ClientKey, ConfigBuilder, FheUint64, FheUint8, MatchValues};

/// Registers a single operation as either a latency or a throughput benchmark,
/// driven by __TFHE_RS_BENCH_TYPE
fn bench_latency_or_throughput<F>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    bench_name: &str,
    type_name: &str,
    num_elements: usize,
    client_key: &ClientKey,
    operand_bits: usize,
    run_once: F,
) -> String
where
    F: Fn() + Sync,
{
    let params = client_key.computation_parameters();
    let params_name = params.name();
    match get_bench_type() {
        BenchmarkType::Latency => {
            let bench_id =
                format!("{bench_name}::{type_name}::{num_elements}_elements::{params_name}");
            group.bench_function(&bench_id, |b| b.iter(&run_once));
            bench_id
        }
        BenchmarkType::Throughput => {
            let num_ops = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    let msg_bits = (params.message_modulus().0 as f64).log2();
                    let num_block = (operand_bits as f64 / msg_bits).ceil() as usize;
                    throughput_num_threads(num_block, 1).max(1) as usize
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    let _ = operand_bits;
                    let setup = |_batch_size: usize| ();
                    let run = |_: &mut (), batch_size: usize| {
                        (0..batch_size).into_par_iter().for_each(|_| run_once());
                    };
                    find_optimal_batch(run, setup)
                }
            };

            let bench_id = format!(
                "{bench_name}::{type_name}::{num_elements}_elements::throughput::{params_name}"
            );
            group.throughput(Throughput::Elements(num_ops as u64));
            group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    (0..num_ops).into_par_iter().for_each(|_| run_once());
                })
            });
            bench_id
        }
    }
}

fn bench_contains_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let bench_name = "hlapi::cuda::contains";
    let mut group = c.benchmark_group(bench_name);
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let cts: Vec<FheUint64> = (0..num_elements as u64)
        .map(|i| FheUint64::encrypt(i, client_key))
        .collect();
    let value = FheUint64::encrypt(1u64, client_key);

    let bench_id = bench_latency_or_throughput(
        &mut group,
        bench_name,
        "FheUint64",
        num_elements,
        client_key,
        num_elements * 64,
        || {
            black_box(FheUint64::contains(&cts, &value));
        },
    );

    write_to_json_unchecked(
        &bench_id,
        params_name,
        "contains",
        &OperatorType::Atomic,
        64,
        vec![params.message_modulus().0.ilog2(); 64],
    );
    group.finish();
}

fn bench_contains_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let bench_name = "hlapi::cuda::contains";
    let mut group = c.benchmark_group(bench_name);
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let cts: Vec<FheUint8> = (0..num_elements)
        .map(|i| FheUint8::encrypt((i % 256) as u8, client_key))
        .collect();
    let value = FheUint8::encrypt(1u8, client_key);

    let bench_id = bench_latency_or_throughput(
        &mut group,
        bench_name,
        "FheUint8",
        num_elements,
        client_key,
        num_elements * 8,
        || {
            black_box(FheUint8::contains(&cts, &value));
        },
    );

    write_to_json_unchecked(
        &bench_id,
        params_name,
        "contains",
        &OperatorType::Atomic,
        8,
        vec![params.message_modulus().0.ilog2(); 8],
    );
    group.finish();
}

fn bench_match_value_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let bench_name = "hlapi::cuda::match_value";
    let mut group = c.benchmark_group(bench_name);
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let pairs: Vec<(u64, u64)> = (0..num_elements as u64).map(|i| (i, i + 1)).collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint64::encrypt(1u64, client_key);

    let bench_id = bench_latency_or_throughput(
        &mut group,
        bench_name,
        "FheUint64",
        num_elements,
        client_key,
        num_elements * 64,
        || {
            let _: (FheUint64, _) = black_box(ct.match_value(&match_values).unwrap());
        },
    );

    write_to_json_unchecked(
        &bench_id,
        params_name,
        "match_value",
        &OperatorType::Atomic,
        64,
        vec![params.message_modulus().0.ilog2(); 64],
    );
    group.finish();
}

fn bench_match_value_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let bench_name = "hlapi::cuda::match_value";
    let mut group = c.benchmark_group(bench_name);
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let limit = std::cmp::min(num_elements, 256);
    let pairs: Vec<(u8, u8)> = (0..limit)
        .map(|i| (i as u8, (i as u8).wrapping_add(1)))
        .collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint8::encrypt(1u8, client_key);

    let bench_id = bench_latency_or_throughput(
        &mut group,
        bench_name,
        "FheUint8",
        num_elements,
        client_key,
        limit * 8,
        || {
            let _: (FheUint8, _) = black_box(ct.match_value(&match_values).unwrap());
        },
    );

    write_to_json_unchecked(
        &bench_id,
        params_name,
        "match_value",
        &OperatorType::Atomic,
        8,
        vec![params.message_modulus().0.ilog2(); 8],
    );
    group.finish();
}

fn main() {
    let env_config = EnvConfig::new();

    #[cfg(feature = "gpu")]
    let client_key = {
        let param: AtomicPatternParameters = match get_param_type() {
            ParamType::Classical => BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
            _ => BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
        };
        let config = ConfigBuilder::with_custom_parameters(param).build();
        let client_key = ClientKey::generate(config);
        configure_gpu(&client_key);
        client_key
    };

    #[cfg(not(feature = "gpu"))]
    let client_key = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS;
        use tfhe::{set_server_key, CompressedServerKey};
        let config =
            ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS).build();
        let client_key = ClientKey::generate(config);
        let sks = CompressedServerKey::new(&client_key).decompress();
        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        client_key
    };

    let mut c = Criterion::default().configure_from_args();

    let sizes: &[usize] = match env_config.bit_sizes_set {
        BitSizesSet::Fast => &[50, 1000],
        _ => &[5, 10, 20, 30, 40, 50, 500, 1000],
    };

    for &size in sizes {
        bench_contains_fhe_uint64(&mut c, &client_key, size);
    }
    for &size in sizes {
        bench_match_value_fhe_uint64(&mut c, &client_key, size);
    }

    for &size in sizes {
        bench_contains_fhe_uint8(&mut c, &client_key, size);
    }
    for &size in sizes {
        bench_match_value_fhe_uint8(&mut c, &client_key, size);
    }

    c.final_summary();
}
