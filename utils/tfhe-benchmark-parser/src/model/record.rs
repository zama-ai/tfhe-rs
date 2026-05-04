use benchmark_spec::OperandType;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) enum PolynomialMultiplication {
    Fft,
    // Ntt,
}

#[derive(Serialize)]
pub(crate) enum IntegerRepresentation {
    Radix,
    // Crt,
    // Hybrid,
}

#[derive(Serialize)]
pub(crate) enum ExecutionType {
    Sequential,
    Parallel,
}

#[derive(Serialize)]
pub(crate) enum KeySetType {
    Single,
    // Multi,
}

#[derive(Clone, Serialize)]
pub enum OperatorType {
    Atomic,
    // AtomicPattern,
}

#[derive(Serialize)]
pub(crate) struct BenchmarkParametersRecord {
    pub display_name: String,
    pub crypto_parameters_alias: String,
    pub ciphertext_modulus: usize,
    pub bit_size: u32,
    pub polynomial_multiplication: PolynomialMultiplication,
    pub integer_representation: IntegerRepresentation,
    pub decomposition_basis: Vec<u32>,
    pub pbs_algorithm: Option<String>,
    pub execution_type: ExecutionType,
    pub key_set_type: KeySetType,
    pub operand_type: OperandType,
    pub operator_type: OperatorType,
}
