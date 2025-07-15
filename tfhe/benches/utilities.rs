use serde::Serialize;
use std::path::PathBuf;
use std::{env, fs};
use std::sync::OnceLock;
use tfhe::core_crypto::prelude::*;

#[cfg(feature = "boolean")]
pub mod boolean_utils {
    use super::*;
    use tfhe::boolean::parameters::BooleanParameters;

    impl From<BooleanParameters> for CryptoParametersRecord<u32> {
        fn from(params: BooleanParameters) -> Self {
            CryptoParametersRecord {
                lwe_dimension: Some(params.lwe_dimension),
                glwe_dimension: Some(params.glwe_dimension),
                polynomial_size: Some(params.polynomial_size),
                lwe_noise_distribution: Some(params.lwe_noise_distribution),
                glwe_noise_distribution: Some(params.glwe_noise_distribution),
                pbs_base_log: Some(params.pbs_base_log),
                pbs_level: Some(params.pbs_level),
                ks_base_log: Some(params.ks_base_log),
                ks_level: Some(params.ks_level),
                ciphertext_modulus: Some(CiphertextModulus::<u32>::new_native()),
                ..Default::default()
            }
        }
    }
}

#[allow(unused_imports)]
#[cfg(feature = "boolean")]
pub use boolean_utils::*;

#[cfg(feature = "shortint")]
pub mod shortint_utils {
    use super::*;
    use itertools::iproduct;
    use std::vec::IntoIter;
    use tfhe::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
    use tfhe::shortint::parameters::list_compression::CompressionParameters;
    #[cfg(feature = "gpu")]
    use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;
    #[cfg(not(feature = "gpu"))]
    use tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS;
    use tfhe::shortint::parameters::{
        ShortintKeySwitchingParameters, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    };
    use tfhe::shortint::PBSParameters;

    /// An iterator that yields a succession of combinations
    /// of parameters and a num_block to achieve a certain bit_size ciphertext
    /// in radix decomposition
    pub struct ParamsAndNumBlocksIter {
        params_and_bit_sizes:
            itertools::Product<IntoIter<tfhe::shortint::PBSParameters>, IntoIter<usize>>,
    }

    impl Default for ParamsAndNumBlocksIter {
        fn default() -> Self {
            let env_config = EnvConfig::new();

            if env_config.is_multi_bit {
                #[cfg(feature = "gpu")]
                let params = vec![PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS.into()];
                #[cfg(not(feature = "gpu"))]
                let params = vec![PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS.into()];

                let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
                Self {
                    params_and_bit_sizes,
                }
            } else {
                // FIXME One set of parameter is tested since we want to benchmark only quickest
                // operations.
                let params = vec![PARAM_MESSAGE_2_CARRY_2_KS_PBS.into()];

                let params_and_bit_sizes = iproduct!(params, env_config.bit_sizes());
                Self {
                    params_and_bit_sizes,
                }
            }
        }
    }

    impl Iterator for ParamsAndNumBlocksIter {
        type Item = (tfhe::shortint::PBSParameters, usize, usize);

        fn next(&mut self) -> Option<Self::Item> {
            let (param, bit_size) = self.params_and_bit_sizes.next()?;
            let num_block =
                (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as usize;

            Some((param, num_block, bit_size))
        }
    }

    impl From<PBSParameters> for CryptoParametersRecord<u64> {
        fn from(params: PBSParameters) -> Self {
            CryptoParametersRecord {
                lwe_dimension: Some(params.lwe_dimension()),
                glwe_dimension: Some(params.glwe_dimension()),
                polynomial_size: Some(params.polynomial_size()),
                lwe_noise_distribution: Some(params.lwe_noise_distribution()),
                glwe_noise_distribution: Some(params.glwe_noise_distribution()),
                pbs_base_log: Some(params.pbs_base_log()),
                pbs_level: Some(params.pbs_level()),
                ks_base_log: Some(params.ks_base_log()),
                ks_level: Some(params.ks_level()),
                message_modulus: Some(params.message_modulus().0),
                carry_modulus: Some(params.carry_modulus().0),
                ciphertext_modulus: Some(
                    params
                        .ciphertext_modulus()
                        .try_to()
                        .expect("failed to convert ciphertext modulus"),
                ),
                ..Default::default()
            }
        }
    }

    impl From<ShortintKeySwitchingParameters> for CryptoParametersRecord<u64> {
        fn from(params: ShortintKeySwitchingParameters) -> Self {
            CryptoParametersRecord {
                ks_base_log: Some(params.ks_base_log),
                ks_level: Some(params.ks_level),
                ..Default::default()
            }
        }
    }

    impl From<CompactPublicKeyEncryptionParameters> for CryptoParametersRecord<u64> {
        fn from(params: CompactPublicKeyEncryptionParameters) -> Self {
            CryptoParametersRecord {
                message_modulus: Some(params.message_modulus.0),
                carry_modulus: Some(params.carry_modulus.0),
                ciphertext_modulus: Some(params.ciphertext_modulus),
                ..Default::default()
            }
        }
    }

    impl From<CompressionParameters> for CryptoParametersRecord<u64> {
        fn from(_params: CompressionParameters) -> Self {
            CryptoParametersRecord {
                ..Default::default()
            }
        }
    }
}

#[allow(unused_imports)]
#[cfg(feature = "shortint")]
pub use shortint_utils::*;
use tfhe_cuda_backend::cuda_bind::cuda_get_number_of_gpus;

#[derive(Clone, Copy, Default, Serialize)]
pub struct CryptoParametersRecord<Scalar: UnsignedInteger> {
    pub lwe_dimension: Option<LweDimension>,
    pub glwe_dimension: Option<GlweDimension>,
    pub polynomial_size: Option<PolynomialSize>,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub lwe_noise_distribution: Option<DynamicDistribution<Scalar>>,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub glwe_noise_distribution: Option<DynamicDistribution<Scalar>>,
    pub pbs_base_log: Option<DecompositionBaseLog>,
    pub pbs_level: Option<DecompositionLevelCount>,
    pub ks_base_log: Option<DecompositionBaseLog>,
    pub ks_level: Option<DecompositionLevelCount>,
    pub pfks_level: Option<DecompositionLevelCount>,
    pub pfks_base_log: Option<DecompositionBaseLog>,
    pub pfks_std_dev: Option<StandardDev>,
    pub cbs_level: Option<DecompositionLevelCount>,
    pub cbs_base_log: Option<DecompositionBaseLog>,
    pub message_modulus: Option<usize>,
    pub carry_modulus: Option<usize>,
    pub ciphertext_modulus: Option<CiphertextModulus<Scalar>>,
}

impl<Scalar: UnsignedInteger> CryptoParametersRecord<Scalar> {
    pub fn noise_distribution_as_string(noise_distribution: DynamicDistribution<Scalar>) -> String {
        match noise_distribution {
            DynamicDistribution::Gaussian(g) => format!("Gaussian({}, {})", g.std, g.mean),
            DynamicDistribution::TUniform(t) => format!("TUniform({})", t.bound_log2()),
        }
    }

    pub fn serialize_distribution<S>(
        noise_distribution: &Option<DynamicDistribution<Scalar>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match noise_distribution {
            Some(d) => serializer.serialize_some(&Self::noise_distribution_as_string(*d)),
            None => serializer.serialize_none(),
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

const FAST_BENCH_BIT_SIZES: [usize; 1] = [64];
const BENCH_BIT_SIZES: [usize; 8] = [4, 8, 16, 32, 40, 64, 128, 256];
const MULTI_BIT_CPU_SIZES: [usize; 6] = [4, 8, 16, 32, 40, 64];

/// User configuration in which benchmarks must be run.
#[derive(Default)]
pub struct EnvConfig {
    pub is_multi_bit: bool,
    pub is_fast_bench: bool,
}

impl EnvConfig {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let is_multi_bit = match env::var("__TFHE_RS_BENCH_TYPE") {
            Ok(val) => val.to_lowercase() == "multi_bit",
            Err(_) => false,
        };

        let is_fast_bench = match env::var("__TFHE_RS_FAST_BENCH") {
            Ok(val) => val.to_lowercase() == "true",
            Err(_) => false,
        };

        EnvConfig {
            is_multi_bit,
            is_fast_bench,
        }
    }

    /// Get precisions values to benchmark.
    #[allow(dead_code)]
    pub fn bit_sizes(&self) -> Vec<usize> {
        if self.is_fast_bench {
            FAST_BENCH_BIT_SIZES.to_vec()
        } else if self.is_multi_bit {
            if cfg!(feature = "gpu") {
                BENCH_BIT_SIZES.to_vec()
            } else {
                MULTI_BIT_CPU_SIZES.to_vec()
            }
        } else {
            BENCH_BIT_SIZES.to_vec()
        }
    }
}

#[allow(dead_code)]
pub fn throughput_num_threads(num_block: usize) -> u64 {
    let ref_block_count = 32; // Represent a ciphertext of 64 bits for 2_2 parameters set
    let block_multiplicator = (ref_block_count as f64 / num_block as f64).ceil();

    #[cfg(feature = "gpu")]
    {
        // This value is for Nvidia H100 GPU
        let streaming_multiprocessors = 132;
        let num_gpus = unsafe { cuda_get_number_of_gpus() };
        ((streaming_multiprocessors * num_gpus) as f64 * block_multiplicator) as u64
    }
    #[cfg(not(feature = "gpu"))]
    {
        let num_threads = rayon::current_num_threads() as f64;
        // Add 20% more to maximum threads available.
        ((num_threads + (num_threads * 0.2)) * block_multiplicator) as u64
    }
}

#[allow(dead_code)]
pub static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();

#[allow(dead_code)]
pub enum BenchmarkType {
    Latency,
    Throughput,
}

#[allow(dead_code)]
impl BenchmarkType {
    pub fn from_env() -> Result<Self, String> {
        let raw_value = env::var("__TFHE_RS_BENCH_TYPE").unwrap_or("latency".to_string());
        match raw_value.to_lowercase().as_str() {
            "latency" => Ok(BenchmarkType::Latency),
            "throughput" => Ok(BenchmarkType::Throughput),
            _ => Err(format!("benchmark type '{raw_value}' is not supported")),
        }
    }
}

// Empty main to please clippy.
#[allow(dead_code)]
pub fn main() {}
