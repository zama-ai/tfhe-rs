use crate::model::record::{
    BenchmarkParametersRecord, ExecutionType, IntegerRepresentation, KeySetType,
    PolynomialMultiplication,
};
use crate::model::{CryptoParametersRecord, OperatorType};
use benchmark_spec::{BenchmarkSpec, OperandType};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use tfhe::core_crypto::prelude::UnsignedInteger;

/// Writes benchmarks parameters to disk in JSON format, enforcing the bench name spec.
pub fn write_to_json<
    Scalar: UnsignedInteger + Serialize,
    T: Into<CryptoParametersRecord<Scalar>>,
>(
    benchmark_spec: &BenchmarkSpec,
    params: T,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u32,
    decomposition_basis: Vec<u32>,
) {
    write_to_json_unchecked(
        &benchmark_spec.to_string(),
        params,
        benchmark_spec.param_name,
        display_name,
        operator_type,
        bit_size,
        decomposition_basis,
    )
}

/// Writes benchmarks parameters to disk in JSON format.
/// Prefer `write_to_json` which enforces the bench name spec via `BenchmarkSpec`.
pub fn write_to_json_unchecked<
    Scalar: UnsignedInteger + Serialize,
    T: Into<CryptoParametersRecord<Scalar>>,
>(
    bench_id: &str,
    params: T,
    params_alias: impl Into<String>,
    display_name: impl Into<String>,
    operator_type: &OperatorType,
    bit_size: u32,
    decomposition_basis: Vec<u32>,
) {
    let params = params.into();

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
        crypto_parameters: params,
        message_modulus: params.message_modulus,
        carry_modulus: params.carry_modulus,
        ciphertext_modulus: 64,
        bit_size,
        polynomial_multiplication: PolynomialMultiplication::Fft,
        precision: (params.message_modulus.unwrap_or(2) as u32).ilog2(),
        error_probability: params.error_probability.unwrap_or(2f64.powf(-41.0)),
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
