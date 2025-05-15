use serde::Serialize;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::{env, fs};
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;
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
    use tfhe::shortint::parameters::compact_public_key_only::CompactPublicKeyEncryptionParameters;
    use tfhe::shortint::parameters::list_compression::CompressionParameters;
    use tfhe::shortint::parameters::ShortintKeySwitchingParameters;
    use tfhe::shortint::{
        AtomicPatternParameters, ClassicPBSParameters, MultiBitPBSParameters, PBSParameters,
        ShortintParameterSet,
    };

    impl From<PBSParameters> for CryptoParametersRecord<u64> {
        fn from(params: PBSParameters) -> Self {
            AtomicPatternParameters::from(params).into()
        }
    }

    impl From<AtomicPatternParameters> for CryptoParametersRecord<u64> {
        fn from(params: AtomicPatternParameters) -> Self {
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

    impl From<(CompressionParameters, ClassicPBSParameters)> for CryptoParametersRecord<u64> {
        fn from((comp_params, pbs_params): (CompressionParameters, ClassicPBSParameters)) -> Self {
            (comp_params, PBSParameters::PBS(pbs_params)).into()
        }
    }

    impl From<(CompressionParameters, MultiBitPBSParameters)> for CryptoParametersRecord<u64> {
        fn from(
            (comp_params, multi_bit_pbs_params): (CompressionParameters, MultiBitPBSParameters),
        ) -> Self {
            (
                comp_params,
                PBSParameters::MultiBitPBS(multi_bit_pbs_params),
            )
                .into()
        }
    }

    impl From<(CompressionParameters, PBSParameters)> for CryptoParametersRecord<u64> {
        fn from((comp_params, pbs_params): (CompressionParameters, PBSParameters)) -> Self {
            let pbs_params = ShortintParameterSet::new_pbs_param_set(pbs_params);
            let lwe_dimension = pbs_params.encryption_lwe_dimension();
            CryptoParametersRecord {
                lwe_dimension: Some(lwe_dimension),
                br_level: Some(comp_params.br_level),
                br_base_log: Some(comp_params.br_base_log),
                packing_ks_level: Some(comp_params.packing_ks_level),
                packing_ks_base_log: Some(comp_params.packing_ks_base_log),
                packing_ks_polynomial_size: Some(comp_params.packing_ks_polynomial_size),
                packing_ks_glwe_dimension: Some(comp_params.packing_ks_glwe_dimension),
                lwe_per_glwe: Some(comp_params.lwe_per_glwe),
                storage_log_modulus: Some(comp_params.storage_log_modulus),
                lwe_noise_distribution: Some(pbs_params.encryption_noise_distribution()),
                packing_ks_key_noise_distribution: Some(
                    comp_params.packing_ks_key_noise_distribution,
                ),
                ciphertext_modulus: Some(pbs_params.ciphertext_modulus()),
                ..Default::default()
            }
        }
    }
}

#[allow(unused_imports)]
#[cfg(feature = "shortint")]
pub use shortint_utils::*;

#[derive(Clone, Copy, Default, Serialize)]
pub struct CryptoParametersRecord<Scalar: UnsignedInteger> {
    pub lwe_dimension: Option<LweDimension>,
    pub glwe_dimension: Option<GlweDimension>,
    pub packing_ks_glwe_dimension: Option<GlweDimension>,
    pub polynomial_size: Option<PolynomialSize>,
    pub packing_ks_polynomial_size: Option<PolynomialSize>,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub lwe_noise_distribution: Option<DynamicDistribution<Scalar>>,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub glwe_noise_distribution: Option<DynamicDistribution<Scalar>>,
    #[serde(serialize_with = "CryptoParametersRecord::serialize_distribution")]
    pub packing_ks_key_noise_distribution: Option<DynamicDistribution<Scalar>>,
    pub pbs_base_log: Option<DecompositionBaseLog>,
    pub pbs_level: Option<DecompositionLevelCount>,
    pub ks_base_log: Option<DecompositionBaseLog>,
    pub ks_level: Option<DecompositionLevelCount>,
    pub pfks_level: Option<DecompositionLevelCount>,
    pub pfks_base_log: Option<DecompositionBaseLog>,
    pub pfks_std_dev: Option<StandardDev>,
    pub cbs_level: Option<DecompositionLevelCount>,
    pub cbs_base_log: Option<DecompositionBaseLog>,
    pub br_level: Option<DecompositionLevelCount>,
    pub br_base_log: Option<DecompositionBaseLog>,
    pub packing_ks_level: Option<DecompositionLevelCount>,
    pub packing_ks_base_log: Option<DecompositionBaseLog>,
    pub message_modulus: Option<u64>,
    pub carry_modulus: Option<u64>,
    pub ciphertext_modulus: Option<CiphertextModulus<Scalar>>,
    pub lwe_per_glwe: Option<LweCiphertextCount>,
    pub storage_log_modulus: Option<CiphertextModulusLog>,
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
    message_modulus: Option<u64>,
    carry_modulus: Option<u64>,
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
const HPU_BENCH_BIT_SIZES: [usize; 5] = [8, 16, 32, 64, 128];
const MULTI_BIT_CPU_SIZES: [usize; 6] = [4, 8, 16, 32, 40, 64];

/// User configuration in which benchmarks must be run.
#[derive(Default)]
pub struct EnvConfig {
    pub is_multi_bit: bool,
    pub is_fast_bench: bool,
}

impl EnvConfig {
    pub fn new() -> Self {
        let is_multi_bit = match env::var("__TFHE_RS_PARAM_TYPE") {
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
            if cfg!(feature = "hpu") {
                HPU_BENCH_BIT_SIZES.to_vec()
            } else {
                BENCH_BIT_SIZES.to_vec()
            }
        }
    }
}

pub static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();

pub enum BenchmarkType {
    Latency,
    Throughput,
}

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

pub fn get_bench_type() -> &'static BenchmarkType {
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap())
}

/// Number of streaming multiprocessors (SM) available on Nvidia H100 GPU
#[cfg(feature = "gpu")]
const H100_PCIE_SM_COUNT: u32 = 114;

/// Generate a number of threads to use to saturate current machine for throughput measurements.
pub fn throughput_num_threads(num_block: usize, op_pbs_count: u64) -> u64 {
    let ref_block_count = 32; // Represent a ciphertext of 64 bits for 2_2 parameters set
    let block_multiplicator = (ref_block_count as f64 / num_block as f64).ceil().min(1.0);
    // Some operations with a high serial workload (e.g. division) would yield an operation
    // loading value so low that the number of elements in the end wouldn't be meaningful.
    let minimum_loading = if num_block < 64 { 0.2 } else { 0.01 };

    #[cfg(feature = "gpu")]
    {
        let total_num_sm = H100_PCIE_SM_COUNT * get_number_of_gpus();
        let operation_loading = ((total_num_sm as u64 / op_pbs_count) as f64).max(minimum_loading);
        let elements = (total_num_sm as f64 * block_multiplicator * operation_loading) as u64;
        elements.min(1500) // This threshold is useful for operation with both a small number of
                           // block and low PBs count.
    }
    #[cfg(not(feature = "gpu"))]
    {
        let num_threads = rayon::current_num_threads() as f64;
        let operation_loading = (num_threads / (op_pbs_count as f64)).max(minimum_loading);
        // Add 20% more to maximum threads available.
        ((num_threads + (num_threads * 0.2)) * block_multiplicator.min(1.0) * operation_loading)
            as u64
    }
}

#[cfg(feature = "gpu")]
mod cuda_utils {
    use tfhe::core_crypto::entities::{
        LweBootstrapKeyOwned, LweKeyswitchKeyOwned, LweMultiBitBootstrapKeyOwned,
        LwePackingKeyswitchKeyOwned,
    };
    use tfhe::core_crypto::gpu::lwe_bootstrap_key::CudaLweBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
    use tfhe::core_crypto::gpu::lwe_multi_bit_bootstrap_key::CudaLweMultiBitBootstrapKey;
    use tfhe::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
    use tfhe::core_crypto::gpu::vec::CudaVec;
    use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
    use tfhe::core_crypto::prelude::{Numeric, UnsignedInteger};
    use tfhe::shortint::server_key::ModulusSwitchNoiseReductionKey;
    use tfhe::{set_server_key, ClientKey, CompressedServerKey, GpuIndex};

    pub const GPU_MAX_SUPPORTED_POLYNOMIAL_SIZE: usize = 16384;

    /// Get vector of CUDA streams that can be directly used for throughput benchmarks in
    /// core_crypto layer.
    pub fn cuda_local_streams_core() -> Vec<CudaStreams> {
        (0..get_number_of_gpus())
            .map(|i| CudaStreams::new_single_gpu(GpuIndex::new(i)))
            .collect::<Vec<_>>()
    }

    /// Computing keys in their CPU flavor.
    pub struct CpuKeys<T: UnsignedInteger> {
        ksk: Option<LweKeyswitchKeyOwned<T>>,
        pksk: Option<LwePackingKeyswitchKeyOwned<T>>,
        bsk: Option<LweBootstrapKeyOwned<T>>,
        multi_bit_bsk: Option<LweMultiBitBootstrapKeyOwned<T>>,
    }

    impl<T: UnsignedInteger> CpuKeys<T> {
        pub fn builder() -> CpuKeysBuilder<T> {
            CpuKeysBuilder::new()
        }
    }

    pub struct CpuKeysBuilder<T: UnsignedInteger> {
        ksk: Option<LweKeyswitchKeyOwned<T>>,
        pksk: Option<LwePackingKeyswitchKeyOwned<T>>,
        bsk: Option<LweBootstrapKeyOwned<T>>,
        multi_bit_bsk: Option<LweMultiBitBootstrapKeyOwned<T>>,
    }

    impl<T: UnsignedInteger> CpuKeysBuilder<T> {
        pub fn new() -> CpuKeysBuilder<T> {
            Self {
                ksk: None,
                pksk: None,
                bsk: None,
                multi_bit_bsk: None,
            }
        }

        pub fn keyswitch_key(mut self, ksk: LweKeyswitchKeyOwned<T>) -> CpuKeysBuilder<T> {
            self.ksk = Some(ksk);
            self
        }

        pub fn packing_keyswitch_key(
            mut self,
            pksk: LwePackingKeyswitchKeyOwned<T>,
        ) -> CpuKeysBuilder<T> {
            self.pksk = Some(pksk);
            self
        }

        pub fn bootstrap_key(mut self, bsk: LweBootstrapKeyOwned<T>) -> CpuKeysBuilder<T> {
            self.bsk = Some(bsk);
            self
        }

        pub fn multi_bit_bootstrap_key(
            mut self,
            mb_bsk: LweMultiBitBootstrapKeyOwned<T>,
        ) -> CpuKeysBuilder<T> {
            self.multi_bit_bsk = Some(mb_bsk);
            self
        }

        pub fn build(self) -> CpuKeys<T> {
            CpuKeys {
                ksk: self.ksk,
                pksk: self.pksk,
                bsk: self.bsk,
                multi_bit_bsk: self.multi_bit_bsk,
            }
        }
    }
    impl<T: UnsignedInteger> Default for CpuKeysBuilder<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Computing keys in their Cuda flavor.
    #[allow(dead_code)]
    pub struct CudaLocalKeys<T: UnsignedInteger> {
        pub ksk: Option<CudaLweKeyswitchKey<T>>,
        pub pksk: Option<CudaLwePackingKeyswitchKey<T>>,
        pub bsk: Option<CudaLweBootstrapKey>,
        pub multi_bit_bsk: Option<CudaLweMultiBitBootstrapKey>,
    }

    #[allow(dead_code)]
    impl<T: UnsignedInteger> CudaLocalKeys<T> {
        pub fn from_cpu_keys(
            cpu_keys: &CpuKeys<T>,
            ms_noise_reduction_key: Option<&ModulusSwitchNoiseReductionKey<u64>>,
            stream: &CudaStreams,
        ) -> Self {
            Self {
                ksk: cpu_keys
                    .ksk
                    .as_ref()
                    .map(|ksk| CudaLweKeyswitchKey::from_lwe_keyswitch_key(ksk, stream)),
                pksk: cpu_keys.pksk.as_ref().map(|pksk| {
                    CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(pksk, stream)
                }),
                bsk: cpu_keys.bsk.as_ref().map(|bsk| {
                    CudaLweBootstrapKey::from_lwe_bootstrap_key(bsk, ms_noise_reduction_key, stream)
                }),
                multi_bit_bsk: cpu_keys.multi_bit_bsk.as_ref().map(|mb_bsk| {
                    CudaLweMultiBitBootstrapKey::from_lwe_multi_bit_bootstrap_key(mb_bsk, stream)
                }),
            }
        }
    }

    /// Instantiate Cuda computing keys to each available GPU.
    pub fn cuda_local_keys_core<T: UnsignedInteger>(
        cpu_keys: &CpuKeys<T>,
        ms_noise_reduction_key: Option<&ModulusSwitchNoiseReductionKey<u64>>,
    ) -> Vec<CudaLocalKeys<T>> {
        let gpu_count = get_number_of_gpus() as usize;
        let mut gpu_keys_vec = Vec::with_capacity(gpu_count);
        for i in 0..gpu_count {
            let stream = CudaStreams::new_single_gpu(GpuIndex::new(i as u32));
            gpu_keys_vec.push(CudaLocalKeys::from_cpu_keys(
                cpu_keys,
                ms_noise_reduction_key,
                &stream,
            ));
        }
        gpu_keys_vec
    }

    pub struct CudaIndexes<T: Numeric> {
        pub d_input: CudaVec<T>,
        pub d_output: CudaVec<T>,
        pub d_lut: CudaVec<T>,
    }

    impl<T: Numeric> CudaIndexes<T> {
        pub fn new(indexes: &[T], stream: &CudaStreams, stream_index: u32) -> Self {
            let length = indexes.len();
            let mut d_input = unsafe { CudaVec::<T>::new_async(length, stream, stream_index) };
            let mut d_output = unsafe { CudaVec::<T>::new_async(length, stream, stream_index) };
            let mut d_lut = unsafe { CudaVec::<T>::new_async(length, stream, stream_index) };
            unsafe {
                d_input.copy_from_cpu_async(indexes.as_ref(), stream, stream_index);
                d_output.copy_from_cpu_async(indexes.as_ref(), stream, stream_index);
                d_lut.copy_from_cpu_async(indexes.as_ref(), stream, stream_index);
            }
            stream.synchronize();

            Self {
                d_input,
                d_output,
                d_lut,
            }
        }
    }

    #[cfg(feature = "integer")]
    pub mod cuda_integer_utils {
        use tfhe::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
        use tfhe::integer::gpu::CudaServerKey;
        use tfhe::integer::ClientKey;
        use tfhe::GpuIndex;

        /// Get number of streams usable for CUDA throughput benchmarks
        fn cuda_num_streams(num_block: usize) -> u64 {
            let num_streams_per_gpu: u32 = match num_block {
                2 => 64,
                4 => 32,
                8 => 16,
                16 => 8,
                32 => 4,
                64 => 2,
                128 => 1,
                _ => 8,
            };
            (num_streams_per_gpu * get_number_of_gpus()) as u64
        }

        /// Get vector of CUDA streams that can be directly used for throughput benchmarks.
        pub fn cuda_local_streams(
            num_block: usize,
            throughput_elements: usize,
        ) -> Vec<CudaStreams> {
            (0..cuda_num_streams(num_block))
                .map(|i| {
                    CudaStreams::new_single_gpu(GpuIndex::new(
                        (i % get_number_of_gpus() as u64) as u32,
                    ))
                })
                .cycle()
                .take(throughput_elements)
                .collect::<Vec<_>>()
        }

        /// Instantiate Cuda server key to each available GPU.
        pub fn cuda_local_keys(cks: &ClientKey) -> Vec<CudaServerKey> {
            let gpu_count = get_number_of_gpus() as usize;
            let mut gpu_sks_vec = Vec::with_capacity(gpu_count);
            for i in 0..gpu_count {
                let stream = CudaStreams::new_single_gpu(GpuIndex::new(i as u32));
                gpu_sks_vec.push(CudaServerKey::new(cks, &stream));
            }
            gpu_sks_vec
        }
    }

    #[allow(dead_code)]
    pub fn configure_gpu(client_key: &ClientKey) {
        let compressed_sks = CompressedServerKey::new(client_key);
        let sks = compressed_sks.decompress_to_gpu();
        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
    }
    #[allow(unused_imports)]
    #[cfg(feature = "integer")]
    pub use cuda_integer_utils::*;
}

#[cfg(feature = "gpu")]
pub use cuda_utils::*;
