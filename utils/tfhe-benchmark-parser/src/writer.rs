use crate::model::OperatorType;
use crate::model::record::{
    BenchmarkParametersRecord, ExecutionType, IntegerRepresentation, KeySetType,
    PolynomialMultiplication,
};
use benchmark_spec::{BenchmarkSpec, OperandType};
use std::fs;
use std::path::PathBuf;

/// Writes benchmarks parameters to disk in JSON format, enforcing the bench name spec.
pub fn write_to_json(
    benchmark_spec: &BenchmarkSpec,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u32,
    decomposition_basis: Vec<u32>,
) {
    write_to_json_unchecked(
        &benchmark_spec.to_string(),
        benchmark_spec.param_name,
        display_name,
        operator_type,
        bit_size,
        decomposition_basis,
    )
}

/// Writes benchmarks parameters to disk in JSON format.
/// Prefer `write_to_json` which enforces the bench name spec via `BenchmarkSpec`.
pub fn write_to_json_unchecked(
    bench_id: &str,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u32,
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
        ciphertext_modulus: 64,
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
