#[path = "../utilities.rs"]
mod utilities;
use crate::utilities::{write_to_json, CryptoParametersRecord, OperatorType};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
    PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
};
use tfhe::boolean::prelude::{BinaryBooleanGates, DEFAULT_PARAMETERS_KS_PBS};
use tfhe::boolean::server_key::ServerKey;

criterion_group!(
    gates_benches,
    bench_default_parameters,
    bench_tfhe_lib_parameters,
    bench_default_parameters_ks_pbs,
    bench_tfhe_lib_parameters_pbs,
);

criterion_main!(gates_benches);

/// Helper function to write boolean benchmarks parameters to disk in JSON format.
pub fn write_to_json_boolean<T: Into<CryptoParametersRecord<u32>>>(
    bench_id: &str,
    params: T,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
) {
    write_to_json(
        bench_id,
        params,
        params_alias,
        display_name,
        &OperatorType::Atomic,
        1,
        vec![1],
    );
}

// Put all `bench_function` in one place
// so the keygen is only run once per parameters saving time.
fn benchs(c: &mut Criterion, params: BooleanParameters, parameter_name: &str) {
    let mut bench_group = c.benchmark_group("gates_benches");

    let cks = ClientKey::new(&params);
    let sks = ServerKey::new(&cks);

    let ct1 = cks.encrypt(true);
    let ct2 = cks.encrypt(false);
    let ct3 = cks.encrypt(true);

    let id = format!("AND::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.and(&ct1, &ct2))));
    write_to_json_boolean(&id, params, parameter_name, "and");

    let id = format!("NAND::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.nand(&ct1, &ct2))));
    write_to_json_boolean(&id, params, parameter_name, "nand");

    let id = format!("OR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.or(&ct1, &ct2))));
    write_to_json_boolean(&id, params, parameter_name, "or");

    let id = format!("XOR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xor(&ct1, &ct2))));
    write_to_json_boolean(&id, params, parameter_name, "xor");

    let id = format!("XNOR::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.xnor(&ct1, &ct2))));
    write_to_json_boolean(&id, params, parameter_name, "xnor");

    let id = format!("NOT::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.not(&ct1))));
    write_to_json_boolean(&id, params, parameter_name, "not");

    let id = format!("MUX::{parameter_name}");
    bench_group.bench_function(&id, |b| b.iter(|| black_box(sks.mux(&ct1, &ct2, &ct3))));
    write_to_json_boolean(&id, params, parameter_name, "mux");
}

fn bench_default_parameters(c: &mut Criterion) {
    benchs(c, DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS");
}

fn bench_tfhe_lib_parameters(c: &mut Criterion) {
    benchs(
        c,
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
        "TFHE_LIB_PARAMETERS",
    );
}
fn bench_default_parameters_ks_pbs(c: &mut Criterion) {
    benchs(c, DEFAULT_PARAMETERS_KS_PBS, "DEFAULT_PARAMETERS_KS_PBS");
}

fn bench_tfhe_lib_parameters_pbs(c: &mut Criterion) {
    benchs(
        c,
        PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS,
        "TFHE_LIB_PARAMETERS_KS_PBS",
    );
}
