#[path = "../utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, OperatorType};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use tfhe::boolean::prelude::BinaryBooleanGates;
use tfhe::boolean::server_key::ServerKey;

criterion_group!(
    gates_benches,
    bench_default_parameters,
    bench_tfhe_lib_parameters
);

criterion_main!(gates_benches);

// Put all `bench_function` in one place
// so the keygen is only run once per parameters saving time.
fn benchs(c: &mut Criterion, params: BooleanParameters, parameter_name: &str) {
    let mut bench_group = c.benchmark_group("gates_benches");

    let cks = ClientKey::new(&params);
    let sks = ServerKey::new(&cks);

    let ct1 = cks.encrypt(true);
    let ct2 = cks.encrypt(false);
    let ct3 = cks.encrypt(true);

    let operator = OperatorType::Atomic;

    let id = format!("AND::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.and(&ct1, &ct2))));
    write_to_json(&id, params, parameter_name, "and", &operator);

    let id = format!("NAND::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.nand(&ct1, &ct2))));
    write_to_json(&id, params, parameter_name, "nand", &operator);

    let id = format!("OR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.or(&ct1, &ct2))));
    write_to_json(&id, params, parameter_name, "or", &operator);

    let id = format!("XOR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xor(&ct1, &ct2))));
    write_to_json(&id, params, parameter_name, "xor", &operator);

    let id = format!("XNOR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xnor(&ct1, &ct2))));
    write_to_json(&id, params, parameter_name, "xnor", &operator);

    let id = format!("NOT::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.not(&ct1))));
    write_to_json(&id, params, parameter_name, "not", &operator);

    let id = format!("MUX::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.mux(&ct1, &ct2, &ct3))));
    write_to_json(&id, params, parameter_name, "mux", &operator);
}

fn bench_default_parameters(c: &mut Criterion) {
    benchs(c, DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS");
}

fn bench_tfhe_lib_parameters(c: &mut Criterion) {
    benchs(c, TFHE_LIB_PARAMETERS, "TFHE_LIB_PARAMETERS");
}
