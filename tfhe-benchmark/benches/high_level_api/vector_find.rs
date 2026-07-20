#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::{configure_gpu, write_to_json, OperatorType};
#[cfg(feature = "gpu")]
use benchmark_spec::tfhe::hlapi::vector_find::VectorFindOp;
#[cfg(feature = "gpu")]
use benchmark_spec::tfhe::hlapi::HlapiBench;
#[cfg(feature = "gpu")]
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, OperandType};
#[cfg(feature = "gpu")]
use criterion::Criterion;
#[cfg(feature = "gpu")]
use std::hint::black_box;
#[cfg(feature = "gpu")]
use tfhe::keycache::NamedParam;
#[cfg(feature = "gpu")]
use tfhe::prelude::*;
#[cfg(feature = "gpu")]
use tfhe::shortint::AtomicPatternParameters;
#[cfg(feature = "gpu")]
use tfhe::{ClientKey, ConfigBuilder, FheUint64, FheUint8, MatchValues};

#[cfg(feature = "gpu")]
fn write_contains_metadata(
    spec: &BenchmarkSpec<str>,
    params: AtomicPatternParameters,
    num_bits: usize,
) {
    write_to_json(
        spec,
        "contains",
        &OperatorType::Atomic,
        num_bits as u32,
        vec![params.message_modulus().0.ilog2(); num_bits],
    );
}

#[cfg(feature = "gpu")]
fn write_match_value_metadata(
    spec: &BenchmarkSpec<str>,
    params: AtomicPatternParameters,
    num_bits: usize,
) {
    write_to_json(
        spec,
        "match_value",
        &OperatorType::Atomic,
        num_bits as u32,
        vec![params.message_modulus().0.ilog2(); num_bits],
    );
}

#[cfg(feature = "gpu")]
fn bench_contains_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::<str>::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::Contains),
        &params_name,
        OperandType::CipherText,
        Some("FheUint64"),
        BenchmarkMetric::Latency,
        Some(num_elements),
    );
    let bench_id = spec.to_string();

    let cts: Vec<FheUint64> = (0..num_elements as u64)
        .map(|i| FheUint64::encrypt(i, client_key))
        .collect();
    let value = FheUint64::encrypt(1u64, client_key);

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            black_box(FheUint64::contains(&cts, &value));
        })
    });

    write_contains_metadata(&spec, params, 64);
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_contains_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::<str>::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::Contains),
        &params_name,
        OperandType::CipherText,
        Some("FheUint8"),
        BenchmarkMetric::Latency,
        Some(num_elements),
    );
    let bench_id = spec.to_string();

    let cts: Vec<FheUint8> = (0..num_elements)
        .map(|i| FheUint8::encrypt((i % 256) as u8, client_key))
        .collect();
    let value = FheUint8::encrypt(1u8, client_key);

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            black_box(FheUint8::contains(&cts, &value));
        })
    });

    write_contains_metadata(&spec, params, 8);
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_match_value_fhe_uint64(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::<str>::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::MatchValue),
        &params_name,
        OperandType::CipherText,
        Some("FheUint64"),
        BenchmarkMetric::Latency,
        Some(num_elements),
    );
    let bench_id = spec.to_string();

    let pairs: Vec<(u64, u64)> = (0..num_elements as u64).map(|i| (i, i + 1)).collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint64::encrypt(1u64, client_key);

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _: (FheUint64, _) = black_box(ct.match_value(&match_values).unwrap());
        })
    });

    write_match_value_metadata(&spec, params, 64);
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_match_value_fhe_uint8(c: &mut Criterion, client_key: &ClientKey, num_elements: usize) {
    let mut group = c.benchmark_group("vector_find");
    group.sample_size(15);

    let params = client_key.computation_parameters();
    let params_name = params.name();
    let spec = BenchmarkSpec::<str>::new_hlapi(
        HlapiBench::VectorFind(VectorFindOp::MatchValue),
        &params_name,
        OperandType::CipherText,
        Some("FheUint8"),
        BenchmarkMetric::Latency,
        Some(num_elements),
    );
    let bench_id = spec.to_string();

    let limit = std::cmp::min(num_elements, 256);
    let pairs: Vec<(u8, u8)> = (0..limit)
        .map(|i| (i as u8, (i as u8).wrapping_add(1)))
        .collect();
    let match_values = MatchValues::new(pairs).unwrap();
    let ct = FheUint8::encrypt(1u8, client_key);

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _: (FheUint8, _) = black_box(ct.match_value(&match_values).unwrap());
        })
    });

    write_match_value_metadata(&spec, params, 8);
    group.finish();
}

#[cfg(feature = "gpu")]
fn main() {
    let param: AtomicPatternParameters =
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

    let config = ConfigBuilder::with_custom_parameters(param).build();
    let client_key = ClientKey::generate(config);

    configure_gpu(&client_key);

    let mut c = Criterion::default().configure_from_args();

    let sizes = [5, 10, 20, 30, 40, 50, 500, 1000];

    for &size in &sizes {
        bench_contains_fhe_uint64(&mut c, &client_key, size);
    }
    for &size in &sizes {
        bench_match_value_fhe_uint64(&mut c, &client_key, size);
    }

    for &size in &sizes {
        bench_contains_fhe_uint8(&mut c, &client_key, size);
    }
    for &size in &sizes {
        bench_match_value_fhe_uint8(&mut c, &client_key, size);
    }

    c.final_summary();
}

#[cfg(not(feature = "gpu"))]
fn main() {
    println!("hlapi-vector-find bench is only available with the `gpu` feature");
}
