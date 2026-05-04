mod backend;
mod bench_crate;
pub mod tfhe;
mod traits;

pub use backend::{Backend, bench_backend_from_cfg};
pub use bench_crate::BenchCrate;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::{env, fmt};
pub use tfhe::hlapi::HlapiBench;
pub use tfhe::{CoreCryptoBench, HlIntegerOp, ShortintBench, TfheLayer};

pub trait TypeName {
    fn type_name(&self) -> String;
}

#[derive(Debug)]
pub struct TypedKeyValue<'a> {
    key: &'a str,
    value: &'a str,
}

impl<'a> TypedKeyValue<'a> {
    pub fn new(key: &'a str, value: &'a str) -> Self {
        Self { key, value }
    }
}

impl TypeName for TypedKeyValue<'_> {
    fn type_name(&self) -> String {
        format!("key_{}::value_{}", self.key, self.value)
    }
}

impl TypeName for str {
    fn type_name(&self) -> String {
        self.to_string()
    }
}

#[derive(Debug)]
pub struct CudaKeyswitchConfig {
    pub bits: u32,
    pub uses_gemm: Option<bool>,
    pub trivial_indices: Option<bool>,
}

impl CudaKeyswitchConfig {
    pub fn new(bits: u32, uses_gemm: Option<bool>, trivial_indices: Option<bool>) -> Self {
        Self {
            bits,
            uses_gemm,
            trivial_indices,
        }
    }
}

impl TypeName for CudaKeyswitchConfig {
    fn type_name(&self) -> String {
        let mut name = format!("{}b", self.bits);
        if let Some(uses_gemm) = self.uses_gemm {
            name.push_str(if uses_gemm { "::gemm" } else { "::classical" });
        }
        if let Some(trivial) = self.trivial_indices {
            name.push_str(if trivial {
                "::trivial_indices"
            } else {
                "::complex_indices"
            });
        }
        name
    }
}

pub struct CsvResultWriter {
    file: File,
}

impl CsvResultWriter {
    pub fn new(file_name: &str) -> Self {
        let file_path = Path::new(file_name);
        Self::from_path(file_path)
    }

    pub fn from_path(path: &Path) -> Self {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("cannot create parent dirs");
            }
            File::create(path).expect("cannot create result file");
        }
        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("cannot open result file");
        Self { file }
    }

    pub fn write_result(&mut self, name: &str, value: usize) {
        let line = format!("{name},{value}\n");
        let error_message = format!("cannot write {name} result into file");
        self.file.write_all(line.as_bytes()).expect(&error_message);
    }
}

#[derive(Debug, Serialize, Clone, Copy)]
pub enum OperandType {
    CipherText,
    PlainText,
}

impl OperandType {
    pub fn is_scalar(&self) -> bool {
        matches!(self, OperandType::PlainText)
    }
}

/// Benchmark type driven by the `__TFHE_RS_BENCH_TYPE` environment variable.
///
/// Only `Latency` and `Throughput` can come from the environment; `PbsCount`
/// is hard-coded at specific call sites.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum BenchmarkType {
    Latency,
    Throughput,
}

/// The metric being recorded by a benchmark, used in [`BenchmarkSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BenchmarkMetric {
    Latency,
    Throughput,
    PbsCount,
    KeySize,
}

impl From<BenchmarkType> for BenchmarkMetric {
    fn from(ct: BenchmarkType) -> Self {
        match ct {
            BenchmarkType::Latency => BenchmarkMetric::Latency,
            BenchmarkType::Throughput => BenchmarkMetric::Throughput,
        }
    }
}

impl FromStr for BenchmarkMetric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latency" => Ok(Self::Latency),
            "throughput" => Ok(Self::Throughput),
            "pbscount" => Ok(Self::PbsCount),
            "keysize" => Ok(Self::KeySize),
            _ => Err(format!("unknown benchmark metric: {s}")),
        }
    }
}

impl BenchmarkType {
    /// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
    fn from_env() -> Result<Self, String> {
        let raw_value = env::var("__TFHE_RS_BENCH_TYPE").unwrap_or("latency".to_string());
        match raw_value.to_lowercase().as_str() {
            "latency" => Ok(BenchmarkType::Latency),
            "throughput" => Ok(BenchmarkType::Throughput),
            _ => Err(format!("benchmark type '{raw_value}' is not supported")),
        }
    }
}

/// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
///
/// Returns only `Latency` or `Throughput` — never `PbsCount`.
pub fn get_bench_type() -> &'static BenchmarkType {
    use std::sync::OnceLock;
    static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap())
}

/// Enforces the naming convention for benchmark IDs.
///
/// ```text
/// {crate}::{layer}::{bench}::{op}(::{backend})?(::{benchmark_type})?::{param}(::scalar)?(::{type})?(::{num_elements}_elements)?
/// ```
///
/// `param_name` is kept as `&str` because it comes from `NamedParam::name()`
/// at runtime. `type_name` is generic over `T: TypeName` so it can be either
/// a `&str` (from `stringify!()` in bench macros) or a structured type like
/// [`TypedKeyValue`].
pub struct BenchmarkSpec<'a, T: TypeName + ?Sized> {
    pub bench_crate: BenchCrate,
    pub backend: Backend,
    pub param_name: &'a str,
    pub operand_type: OperandType,
    pub type_name: Option<&'a T>,
    pub bench_type: BenchmarkMetric,
    pub num_elements: Option<usize>,
}

impl<'a, T: TypeName + ?Sized> BenchmarkSpec<'a, T> {
    pub fn new(
        bench_crate: BenchCrate,
        backend: Backend,
        param_name: &'a str,
        operand_type: OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate,
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_hlapi_ops(
        hlapi_op: HlIntegerOp,
        param_name: &'a str,
        operand_type: OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(hlapi_op))),
            backend: bench_backend_from_cfg(),
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_hlapi(
        hlapi_bench: HlapiBench,
        param_name: &'a str,
        operand_type: OperandType,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<usize>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(hlapi_bench)),
            backend: bench_backend_from_cfg(),
            param_name,
            operand_type,
            type_name,
            bench_type: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_shortint(
        shortint_bench: ShortintBench,
        param_name: &'a str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Shortint(shortint_bench)),
            backend: bench_backend_from_cfg(),
            param_name,
            operand_type: OperandType::CipherText,
            type_name: None,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_core_crypto(
        core_crypto_bench: CoreCryptoBench,
        param_name: &'a str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::CoreCrypto(core_crypto_bench)),
            backend: bench_backend_from_cfg(),
            param_name,
            operand_type: OperandType::CipherText,
            type_name: None,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_cuda_core_crypto(
        core_crypto_bench: CoreCryptoBench,
        param_name: &'a str,
        type_name: Option<&'a T>,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::CoreCrypto(core_crypto_bench)),
            backend: bench_backend_from_cfg(),
            param_name,
            operand_type: OperandType::CipherText,
            type_name,
            bench_type: bench_type.into(),
            num_elements: None,
        }
    }
}

impl<T: TypeName + ?Sized> fmt::Display for BenchmarkSpec<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bench_crate.fmt_crate(f)?;
        if !matches!(self.backend, Backend::Cpu) {
            write!(f, "::{}", self.backend)?;
        }
        match self.bench_type {
            BenchmarkMetric::Throughput => write!(f, "::throughput")?,
            BenchmarkMetric::PbsCount => write!(f, "::pbs_count")?,
            BenchmarkMetric::KeySize => write!(f, "::key_size")?,
            BenchmarkMetric::Latency => {}
        }
        write!(f, "::{}", self.param_name)?;
        if self.operand_type.is_scalar() {
            write!(f, "::scalar")?;
        }
        if let Some(type_name) = self.type_name {
            write!(f, "::{}", type_name.type_name())?;
        }
        if let Some(num_elements) = self.num_elements {
            write!(f, "::{num_elements}_elements")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tfhe::hlapi::dex::Dex;
    use crate::tfhe::hlapi::erc7984::Erc7984;

    use super::*;

    #[test]
    fn hlapi_cpu_latency() {
        let spec = BenchmarkSpec::new_hlapi_ops(
            HlIntegerOp::Add,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::add::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_cuda_latency() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Mul))),
            Backend::Cuda,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint128"),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::mul::cuda::PARAM_MESSAGE_2_CARRY_2::FheUint128"
        );
    }

    #[test]
    fn hlapi_hpu_throughput() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Add))),
            Backend::Hpu,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Throughput,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::add::hpu::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_scalar() {
        let spec = BenchmarkSpec::new_hlapi_ops(
            HlIntegerOp::LeftShift,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::PlainText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
        );
    }

    #[test]
    fn hlapi_no_type_name() {
        let spec = BenchmarkSpec::<str>::new_hlapi_ops(
            HlIntegerOp::Neg,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::neg::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_erc7984_with_num_elements() {
        use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

        let spec = BenchmarkSpec::<str>::new_hlapi(
            HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Whitepaper)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            Some(10),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::whitepaper::PARAM_MESSAGE_2_CARRY_2::10_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_without_num_elements() {
        use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

        let spec = BenchmarkSpec::<str>::new_hlapi(
            HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::NoCmux)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::no_cmux::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_erc7984_num_elements_with_backend() {
        use crate::tfhe::hlapi::erc7984::TransferFlavor;

        let spec = BenchmarkSpec::<str>::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(Erc7984::Transfer(
                TransferFlavor::Overflow,
            )))),
            Backend::Cuda,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::Latency,
            Some(5),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::overflow::cuda::PARAM_MESSAGE_2_CARRY_2::5_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_num_elements_with_throughput() {
        use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

        let spec = BenchmarkSpec::<str>::new_hlapi(
            HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Safe)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::Throughput,
            Some(20),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::safe::throughput::PARAM_MESSAGE_2_CARRY_2::20_elements"
        );
    }

    #[test]
    fn hlapi_erc7984_with_pbs_count() {
        use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

        let spec = BenchmarkSpec::<str>::new_hlapi(
            HlapiBench::Erc7984(Erc7984::Transfer(TransferFlavor::Safe)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            None,
            BenchmarkMetric::PbsCount,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::erc7984::transfer::safe::pbs_count::PARAM_MESSAGE_2_CARRY_2"
        );
    }

    #[test]
    fn hlapi_dex_swap_request_latency() {
        use crate::tfhe::hlapi::dex::{Dex, DexFlavor};

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::Dex(Dex::SwapRequest(DexFlavor::Whitepaper)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_request::whitepaper::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_dex_swap_claim_throughput_with_elements() {
        use crate::tfhe::hlapi::dex::DexFlavor;

        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Dex(Dex::SwapClaim(
                DexFlavor::NoCmux,
            )))),
            Backend::Cuda,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::Throughput,
            Some(10),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_claim::no_cmux::cuda::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64::10_elements"
        );
    }

    #[test]
    fn hlapi_dex_with_pbs_count() {
        use crate::tfhe::hlapi::dex::{Dex, DexFlavor};

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::Dex(Dex::SwapRequest(DexFlavor::Finalize)),
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some("FheUint64"),
            BenchmarkMetric::PbsCount,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_request::finalize::pbs_count::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }
}
