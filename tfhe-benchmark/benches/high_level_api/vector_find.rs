use benchmark::high_level_api::type_display::TypeTagExt;
use benchmark::utilities::{write_to_json, BitSizesSet, EnvConfig, OperatorType};
use benchmark_spec::tfhe::hlapi::vector_find::VectorFindOp;
use benchmark_spec::tfhe::hlapi::HlapiBench;
use benchmark_spec::{get_bench_type, BenchmarkSpec, BenchmarkType, OperandType};
use criterion::{Criterion, Throughput};
use rayon::prelude::*;
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::AtomicPatternParameters;
use tfhe::{ClientKey, ConfigBuilder, FheUint64, FheUint8, MatchValues};

fn write_metadata(
    spec: &BenchmarkSpec,
    display_name: &str,
    params: AtomicPatternParameters,
    num_bits: u32,
) {
    write_to_json(
        spec,
        display_name,
        &OperatorType::Atomic,
        num_bits,
        vec![params.message_modulus().0.ilog2(); num_bits as usize],
    );
}

fn bench_latency_or_throughput<F>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    spec: &BenchmarkSpec,
    operand_bits: u32,
    client_key: &ClientKey,
    run_once: F,
) where
    F: Fn() + Sync,
{
    let bench_id = spec.to_string();
    match get_bench_type() {
        BenchmarkType::Latency => {
            group.bench_function(&bench_id, |b| b.iter(&run_once));
        }
        BenchmarkType::Throughput => {
            let num_ops = {
                #[cfg(any(feature = "gpu", feature = "hpu"))]
                {
                    use benchmark::utilities::throughput_num_threads;
                    let params = client_key.computation_parameters();
                    let msg_bits = (params.message_modulus().0 as f64).log2();
                    let num_block = (operand_bits as f64 / msg_bits).ceil() as usize;
                    throughput_num_threads(num_block, 1).max(1) as usize
                }
                #[cfg(not(any(feature = "gpu", feature = "hpu")))]
                {
                    use benchmark::find_optimal_batch::find_optimal_batch;
                    let _ = (operand_bits, client_key);
                    let setup = |_batch_size: usize| ();
                    let run = |_: &mut (), batch_size: usize| {
                        (0..batch_size).into_par_iter().for_each(|_| run_once());
                    };
                    find_optimal_batch(run, setup)
                }
            };

            group.throughput(Throughput::Elements(num_ops as u64));
            group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    (0..num_ops).into_par_iter().for_each(|_| run_once());
                })
            });
        }
    }
}

fn bench_contains_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: u32) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::Contains),
        &params_name,
        OperandType::CipherText,
        Some(FheUint64::type_tag()),
        get_bench_type(),
        Some(num_elements),
    );
    let cts: Vec<FheUint64> = (0..num_elements as u64)
        .map(|i| FheUint64::encrypt(i, client_key))
        .collect();
    let value = FheUint64::encrypt(1u64, client_key);

    bench_latency_or_throughput(&mut group, &spec, num_elements * 64, client_key, || {
        black_box(FheUint64::contains(&cts, &value));
    });

    write_metadata(&spec, "contains", params, 64);
    group.finish();
}

fn bench_contains_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: u32) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::Contains),
        &params_name,
        OperandType::CipherText,
        Some(FheUint8::type_tag()),
        get_bench_type(),
        Some(num_elements),
    );
    let cts: Vec<FheUint8> = (0..num_elements)
        .map(|i| FheUint8::encrypt((i % 256) as u8, client_key))
        .collect();
    let value = FheUint8::encrypt(1u8, client_key);

    bench_latency_or_throughput(&mut group, &spec, num_elements * 8, client_key, || {
        black_box(FheUint8::contains(&cts, &value));
    });

    write_metadata(&spec, "contains", params, 8);
    group.finish();
}

fn bench_match_value_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: u32) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::MatchValue),
        &params_name,
        OperandType::CipherText,
        Some(FheUint64::type_tag()),
        get_bench_type(),
        Some(num_elements),
    );
    let pairs: Vec<(u64, u64)> = (0..num_elements as u64).map(|i| (i, i + 1)).collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint64::encrypt(1u64, client_key);

    bench_latency_or_throughput(&mut group, &spec, num_elements * 64, client_key, || {
        let _: (FheUint64, _) = black_box(ct.match_value(&match_values).unwrap());
    });

    write_metadata(&spec, "match_value", params, 64);
    group.finish();
}

fn bench_match_value_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: u32) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::MatchValue),
        &params_name,
        OperandType::CipherText,
        Some(FheUint8::type_tag()),
        get_bench_type(),
        Some(num_elements),
    );
    let limit = std::cmp::min(num_elements, 256);
    let pairs: Vec<(u8, u8)> = (0..limit)
        .map(|i| (i as u8, (i as u8).wrapping_add(1)))
        .collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint8::encrypt(1u8, client_key);

    bench_latency_or_throughput(&mut group, &spec, limit * 8, client_key, || {
        let _: (FheUint8, _) = black_box(ct.match_value(&match_values).unwrap());
    });

    write_metadata(&spec, "match_value", params, 8);
    group.finish();
}

#[cfg(feature = "gpu")]
fn build_client_key() -> ClientKey {
    use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use benchmark::utilities::configure_gpu;

    let param: AtomicPatternParameters =
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();
    let config = ConfigBuilder::with_custom_parameters(param).build();
    let client_key = ClientKey::generate(config);
    configure_gpu(&client_key);
    client_key
}

#[cfg(not(feature = "gpu"))]
fn build_client_key() -> ClientKey {
    use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS;
    use tfhe::{set_server_key, CompressedServerKey};

    let config =
        ConfigBuilder::with_custom_parameters(BENCH_PARAM_MESSAGE_2_CARRY_2_KS32_PBS).build();
    let client_key = ClientKey::generate(config);
    let sks = CompressedServerKey::new(&client_key).decompress();
    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);
    client_key
}

fn main() {
    let client_key = build_client_key();

    let mut c = Criterion::default().configure_from_args();

    let env_config = EnvConfig::new();
    let sizes: &[u32] = match env_config.bit_sizes_set {
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
