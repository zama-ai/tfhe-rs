use serde::Serialize;
use std::fs;
use std::path::PathBuf;
#[cfg(feature = "boolean")]
use tfhe::boolean::parameters::BooleanParameters;
use tfhe::core_crypto::prelude::*;
#[cfg(feature = "shortint")]
use tfhe::shortint::parameters::ShortintKeySwitchingParameters;
#[cfg(feature = "shortint")]
use tfhe::shortint::PBSParameters;

#[derive(Clone, Copy, Default, Serialize)]
pub struct CryptoParametersRecord<Scalar: UnsignedInteger> {
    pub lwe_dimension: Option<LweDimension>,
    pub glwe_dimension: Option<GlweDimension>,
    pub polynomial_size: Option<PolynomialSize>,
    pub lwe_modular_std_dev: Option<StandardDev>,
    pub glwe_modular_std_dev: Option<StandardDev>,
    pub pbs_base_log: Option<DecompositionBaseLog>,
    pub pbs_level: Option<DecompositionLevelCount>,
    pub ks_base_log: Option<DecompositionBaseLog>,
    pub ks_level: Option<DecompositionLevelCount>,
    pub pfks_level: Option<DecompositionLevelCount>,
    pub pfks_base_log: Option<DecompositionBaseLog>,
    pub pfks_modular_std_dev: Option<StandardDev>,
    pub cbs_level: Option<DecompositionLevelCount>,
    pub cbs_base_log: Option<DecompositionBaseLog>,
    pub message_modulus: Option<usize>,
    pub carry_modulus: Option<usize>,
    pub ciphertext_modulus: Option<CiphertextModulus<Scalar>>,
}

#[cfg(feature = "boolean")]
impl<Scalar: UnsignedInteger> From<BooleanParameters> for CryptoParametersRecord<Scalar> {
    fn from(params: BooleanParameters) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(params.lwe_dimension),
            glwe_dimension: Some(params.glwe_dimension),
            polynomial_size: Some(params.polynomial_size),
            lwe_modular_std_dev: Some(params.lwe_modular_std_dev),
            glwe_modular_std_dev: Some(params.glwe_modular_std_dev),
            pbs_base_log: Some(params.pbs_base_log),
            pbs_level: Some(params.pbs_level),
            ks_base_log: Some(params.ks_base_log),
            ks_level: Some(params.ks_level),
            pfks_level: None,
            pfks_base_log: None,
            pfks_modular_std_dev: None,
            cbs_level: None,
            cbs_base_log: None,
            message_modulus: None,
            carry_modulus: None,
            ciphertext_modulus: Some(CiphertextModulus::<Scalar>::new_native()),
        }
    }
}

#[cfg(feature = "shortint")]
impl<Scalar> From<PBSParameters> for CryptoParametersRecord<Scalar>
where
    Scalar: UnsignedInteger + CastInto<u128>,
{
    fn from(params: PBSParameters) -> Self {
        CryptoParametersRecord {
            lwe_dimension: Some(params.lwe_dimension()),
            glwe_dimension: Some(params.glwe_dimension()),
            polynomial_size: Some(params.polynomial_size()),
            lwe_modular_std_dev: Some(params.lwe_modular_std_dev()),
            glwe_modular_std_dev: Some(params.glwe_modular_std_dev()),
            pbs_base_log: Some(params.pbs_base_log()),
            pbs_level: Some(params.pbs_level()),
            ks_base_log: Some(params.ks_base_log()),
            ks_level: Some(params.ks_level()),
            pfks_level: None,
            pfks_base_log: None,
            pfks_modular_std_dev: None,
            cbs_level: None,
            cbs_base_log: None,
            message_modulus: Some(params.message_modulus().0),
            carry_modulus: Some(params.carry_modulus().0),
            ciphertext_modulus: Some(
                params
                    .ciphertext_modulus()
                    .try_to()
                    .expect("failed to convert ciphertext modulus"),
            ),
        }
    }
}

#[cfg(feature = "shortint")]
impl<Scalar: UnsignedInteger> From<ShortintKeySwitchingParameters>
    for CryptoParametersRecord<Scalar>
{
    fn from(params: ShortintKeySwitchingParameters) -> Self {
        CryptoParametersRecord {
            lwe_dimension: None,
            glwe_dimension: None,
            polynomial_size: None,
            lwe_modular_std_dev: None,
            glwe_modular_std_dev: None,
            pbs_base_log: None,
            pbs_level: None,
            ks_base_log: Some(params.ks_base_log),
            ks_level: Some(params.ks_level),
            pfks_level: None,
            pfks_base_log: None,
            pfks_modular_std_dev: None,
            cbs_level: None,
            cbs_base_log: None,
            message_modulus: None,
            carry_modulus: None,
            ciphertext_modulus: None,
        }
    }
}

#[derive(Serialize)]
enum PolynomialMultiplication {
    Fft,
    // Ntt,
}

#[derive(Serialize)]
enum IntegerRepresentation {
    Radix,
    // Crt,
    // Hybrid,
}

#[derive(Serialize)]
enum ExecutionType {
    Sequential,
    Parallel,
}

#[derive(Serialize)]
enum KeySetType {
    Single,
    // Multi,
}

#[derive(Serialize)]
enum OperandType {
    CipherText,
    PlainText,
}

#[derive(Clone, Serialize)]
pub enum OperatorType {
    Atomic,
    // AtomicPattern,
}

#[derive(Serialize)]
struct BenchmarkParametersRecord<Scalar: UnsignedInteger> {
    display_name: String,
    crypto_parameters_alias: String,
    crypto_parameters: CryptoParametersRecord<Scalar>,
    message_modulus: Option<usize>,
    carry_modulus: Option<usize>,
    ciphertext_modulus: usize,
    bit_size: u32,
    polynomial_multiplication: PolynomialMultiplication,
    precision: u32,
    error_probability: f64,
    integer_representation: IntegerRepresentation,
    decomposition_basis: Vec<u32>,
    pbs_algorithm: Option<String>,
    execution_type: ExecutionType,
    key_set_type: KeySetType,
    operand_type: OperandType,
    operator_type: OperatorType,
}

/// Writes benchmarks parameters to disk in JSON format.
pub fn write_to_json<
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
        crypto_parameters: params.to_owned(),
        message_modulus: params.message_modulus,
        carry_modulus: params.carry_modulus,
        ciphertext_modulus: 64,
        bit_size,
        polynomial_multiplication: PolynomialMultiplication::Fft,
        precision: (params.message_modulus.unwrap_or(2) as u32).ilog2(),
        error_probability: 2f64.powf(-41.0),
        integer_representation: IntegerRepresentation::Radix,
        decomposition_basis,
        pbs_algorithm: None, // To be added in future version
        execution_type,
        key_set_type: KeySetType::Single,
        operand_type,
        operator_type: operator_type.to_owned(),
    };

    let mut params_directory = ["benchmarks_parameters", bench_id]
        .iter()
        .collect::<PathBuf>();
    fs::create_dir_all(&params_directory).unwrap();
    params_directory.push("parameters.json");

    fs::write(params_directory, serde_json::to_string(&record).unwrap()).unwrap();
}

// Empty main to please clippy.
#[allow(dead_code)]
pub fn main() {}
