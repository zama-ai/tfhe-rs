use crate::model::OperatorType;
use crate::model::record::{
    BenchmarkParametersRecord, ExecutionType, IntegerRepresentation, KeySetType,
    PolynomialMultiplication,
};
use benchmark_spec::{BenchmarkSpec, OperandType};
use std::fs;
use std::path::PathBuf;

/// Writes benchmark parameters to disk in JSON format, enforcing the benchmark name spec.
pub fn write_to_json(
    benchmark_spec: &BenchmarkSpec,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u64,
    decomposition_basis: Vec<u32>,
) {
    write_record(
        &benchmark_spec.to_string(),
        benchmark_spec.param_name().to_string(),
        display_name,
        operator_type,
        bit_size,
        decomposition_basis,
    )
}

/// Writes benchmark parameters for a benchmark whose id was produced outside of
/// Rust, so that no [`BenchmarkSpec`] can be built for it.
///
/// The only such benchmarks are the wasm ones: their names come from the
/// JavaScript harness. Everything else must go through [`write_to_json`].
pub fn write_to_json_external_name(
    bench_id: &str,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u64,
    decomposition_basis: Vec<u32>,
) {
    write_record(
        bench_id,
        params_alias,
        display_name,
        operator_type,
        bit_size,
        decomposition_basis,
    )
}

fn write_record(
    bench_id: &str,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u64,
    decomposition_basis: Vec<u32>,
) {
    let execution_type = match bench_id.contains("parallelized") {
        true => ExecutionType::Parallel,
        false => ExecutionType::Sequential,
    };
    let operand_type = match bench_id.contains("scalar") {
        true => OperandType::PlainText,
        false => OperandType::CipherText,
    };

    let record = BenchmarkParametersRecord {
        display_name: display_name.into(),
        crypto_parameters_alias: params_alias.into(),
        bit_size,
        polynomial_multiplication: PolynomialMultiplication::Fft,
        integer_representation: IntegerRepresentation::Radix,
        decomposition_basis,
        pbs_algorithm: None, // To be added in future version
        execution_type,
        key_set_type: KeySetType::Single,
        operand_type,
        operator_type: operator_type.clone(),
    };

    let mut params_directory = PathBuf::from("benchmarks_parameters").join(bench_id);
    fs::create_dir_all(&params_directory).unwrap();
    params_directory.push("parameters.json");

    fs::write(params_directory, serde_json::to_string(&record).unwrap()).unwrap();
}
