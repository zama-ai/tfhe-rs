use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, BooleanBench};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165, PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
    TFHE_LIB_PARAMETERS,
};
use tfhe::boolean::prelude::BinaryBooleanGates;
use tfhe::boolean::server_key::ServerKey;

criterion_group!(
    gates_benches,
    bench_default_parameters,
    bench_default_parameters_ks_pbs,
    bench_low_prob_parameters,
    bench_low_prob_parameters_ks_pbs,
    bench_tfhe_lib_parameters,
);

criterion_main!(gates_benches);

// Put all `bench_function` in one place
// so the keygen is only run once per parameters saving time.
fn benches(c: &mut Criterion, params: BooleanParameters, parameter_name: &str) {
    let mut bench_group = c.benchmark_group("gates_benches");

    let cks = ClientKey::new(&params);
    let sks = ServerKey::new(&cks);

    let ct1 = cks.encrypt(true);
    let ct2 = cks.encrypt(false);
    let ct3 = cks.encrypt(true);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::And,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.and(&ct1, &ct2))));
    write_to_json(&spec, "and", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Nand,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.nand(&ct1, &ct2))));
    write_to_json(&spec, "nand", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Or,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.or(&ct1, &ct2))));
    write_to_json(&spec, "or", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Xor,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xor(&ct1, &ct2))));
    write_to_json(&spec, "xor", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Xnor,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xnor(&ct1, &ct2))));
    write_to_json(&spec, "xnor", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Not,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.not(&ct1))));
    write_to_json(&spec, "not", &OperatorType::Atomic, 1, vec![1]);

    let spec = BenchmarkSpec::<str>::new_boolean(
        BooleanBench::Mux,
        parameter_name,
        BenchmarkMetric::Latency,
    );
    let id = spec.to_string();
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.mux(&ct1, &ct2, &ct3))));
    write_to_json(&spec, "mux", &OperatorType::Atomic, 1, vec![1]);
}

fn bench_default_parameters(c: &mut Criterion) {
    benches(c, DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS");
}

fn bench_default_parameters_ks_pbs(c: &mut Criterion) {
    benches(c, DEFAULT_PARAMETERS_KS_PBS, "DEFAULT_PARAMETERS_KS_PBS");
}

fn bench_low_prob_parameters(c: &mut Criterion) {
    benches(
        c,
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
        "PARAMETERS_ERROR_PROB_2_POW_MINUS_165",
    );
}

fn bench_low_prob_parameters_ks_pbs(c: &mut Criterion) {
    benches(
        c,
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
        "PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS",
    );
}

fn bench_tfhe_lib_parameters(c: &mut Criterion) {
    benches(c, TFHE_LIB_PARAMETERS, " TFHE_LIB_PARAMETERS");
}
