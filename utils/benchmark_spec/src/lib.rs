mod backend;
mod bench_path;
mod error;
mod measured;
mod parse;
mod segment;
pub mod tfhe;
mod traits;
pub mod zk;

use crate::segment::OptionalSegment;
pub use backend::{Backend, bench_backend_from_cfg};
pub use bench_path::{BenchPath, BenchPathKind};
pub use error::SpecParseError;
pub use measured::{MeasuredId, Statistic, measured_name};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use std::{env, fmt};
use strum::{EnumString, IntoStaticStr};
pub use tfhe::hlapi::HlapiBench;
pub use tfhe::{
    BooleanBench, CoreCryptoBench, HlIntegerOp, IntegerBench, IntegerOp, IntegerOpBySign,
    IntegerOprf, IntegerPackingOp, IntegerRerandMode, ShortintBench, ShortintCastingOp, ShortintOp,
    ShortintPackingOp, TfheLayer,
};

use crate::tfhe::TranscipheringBench;
use crate::zk::ZkLayer;
use crate::zk::msm::MsmBench;

pub trait TypeName {
    fn type_name(&self) -> String;
}

impl fmt::Display for dyn TypeName + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.type_name())
    }
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

#[derive(Debug, Clone, Copy)]
pub enum PrecisionTag {
    /// `{n}_bits`
    Bits(usize),
    /// `{n}_bits_scalar_{n}`
    BitsScalar(usize),
    /// `{from}_to_{to}`
    Conversion { from: usize, to: usize },
}

impl TypeName for PrecisionTag {
    fn type_name(&self) -> String {
        match *self {
            Self::Bits(n) => format!("{n}_bits"),
            Self::BitsScalar(n) => format!("{n}_bits_scalar_{n}"),
            Self::Conversion { from, to } => format!("{from}_to_{to}"),
        }
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

#[derive(Debug, Serialize, Clone, Copy, IntoStaticStr, EnumString, PartialEq, Eq, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum OperandType {
    CipherText,
    #[strum(serialize = "scalar")]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, IntoStaticStr, EnumString,
)]
#[strum(serialize_all = "snake_case")]
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

impl FromStr for BenchmarkType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latency" => Ok(Self::Latency),
            "throughput" => Ok(Self::Throughput),
            _ => Err(format!("benchmark type '{s}' is not supported")),
        }
    }
}

static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();

/// Retrieves the benchmark type from the environment variable `__TFHE_RS_BENCH_TYPE`.
/// Panics if the variable is set to anything other than `latency` or `throughput`.
pub fn get_bench_type() -> BenchmarkType {
    *BENCH_TYPE.get_or_init(|| {
        env::var("__TFHE_RS_BENCH_TYPE")
            .as_deref()
            .unwrap_or("latency")
            .parse()
            .unwrap()
    })
}

/// Enforces the naming convention for benchmark IDs.
///
/// ```text
/// {crate}::{layer}::{bench}::{op}(::{backend})?(::{benchmark_type})?::{param}(::scalar)?(::{type})?(::{num_elements}_elements)?
/// ```
#[derive(Debug)]
pub struct BenchmarkSpec {
    bench_path: BenchPath,
    backend: Backend,
    param_name: String,
    operand_type: OperandType,
    type_name: Option<String>,
    metric: BenchmarkMetric,
    num_elements: Option<u32>,
}

impl BenchmarkSpec {
    /// The benchmarked operation, as a path (`tfhe::hlapi::ops::add`).
    pub fn bench_path(&self) -> BenchPath {
        self.bench_path
    }

    /// The parameter set name (from `NamedParam::name()`).
    pub fn param_name(&self) -> &str {
        &self.param_name
    }

    /// What the recorded value is: a duration, a rate, a count or a byte size.
    pub fn metric(&self) -> BenchmarkMetric {
        self.metric
    }

    /// Whether the second operand is a plaintext (a `scalar` benchmark).
    pub fn operand_type(&self) -> OperandType {
        self.operand_type
    }

    /// The type tag, rendered. Still a flat string: it carries a Rust type, a
    /// precision, a key/value pair or a keyswitch config depending on the
    /// benchmark, so callers have to interpret it.
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    /// `Some` when the id ends with an `<n>_elements` segment: batch size for a
    /// throughput benchmark, store size for a KV-store one.
    pub fn num_elements(&self) -> Option<u32> {
        self.num_elements
    }

    pub fn new(
        bench_path: BenchPath,
        backend: Backend,
        param_name: &str,
        operand_type: OperandType,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<u32>,
    ) -> Self {
        Self {
            bench_path,
            backend,
            param_name: param_name.to_string(),
            operand_type,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_hlapi_ops(
        hlapi_op: HlIntegerOp,
        param_name: &str,
        operand_type: OperandType,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(hlapi_op))),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_hlapi(
        hlapi_bench: HlapiBench,
        param_name: &str,
        operand_type: OperandType,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<u32>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Hlapi(hlapi_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_integer_ops(
        ops: IntegerOpBySign,
        param_name: &str,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<u32>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Integer(IntegerBench::Ops(ops))),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_integer(
        integer_bench: IntegerBench,
        param_name: &str,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<u32>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Integer(integer_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements,
        }
    }

    pub fn new_shortint(
        shortint_bench: ShortintBench,
        param_name: &str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Shortint(shortint_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: None,
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_boolean(
        boolean_bench: BooleanBench,
        param_name: &str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Boolean(boolean_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: None,
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_core_crypto(
        core_crypto_bench: CoreCryptoBench,
        param_name: &str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::CoreCrypto(core_crypto_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: None,
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_cuda_core_crypto(
        core_crypto_bench: CoreCryptoBench,
        param_name: &str,
        type_name: Option<&dyn TypeName>,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::CoreCrypto(core_crypto_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: type_name.map(|t| t.type_name()),
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_transciphering(
        transcipher_bench: TranscipheringBench,
        param_name: &str,
        bench_type: impl Into<BenchmarkMetric>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Tfhe(TfheLayer::Transciphering(transcipher_bench)),
            backend: bench_backend_from_cfg(),
            param_name: param_name.to_string(),
            operand_type: OperandType::CipherText,
            type_name: None,
            metric: bench_type.into(),
            num_elements: None,
        }
    }

    pub fn new_zk_msm(
        zk_bench: MsmBench,
        backend: Backend,
        bench_type: impl Into<BenchmarkMetric>,
        num_elements: Option<u32>,
    ) -> Self {
        Self {
            bench_path: BenchPath::Zk(ZkLayer::Msm(zk_bench)),
            backend,
            param_name: String::new(),
            operand_type: OperandType::CipherText,
            type_name: None,
            metric: bench_type.into(),
            num_elements,
        }
    }
}

impl fmt::Display for BenchmarkSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.bench_path)?;
        if let Some(segment) = self.backend.segment() {
            write!(f, "::{segment}")?;
        }
        if let Some(segment) = self.metric.segment() {
            write!(f, "::{segment}")?;
        }
        if !self.param_name.is_empty() {
            write!(f, "::{}", self.param_name)?;
        }
        if let Some(segment) = self.operand_type.segment() {
            write!(f, "::{segment}")?;
        }
        if let Some(type_name) = &self.type_name {
            write!(f, "::{type_name}")?;
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

    struct Ty(&'static str);

    impl TypeName for Ty {
        fn type_name(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn hlapi_cpu_latency() {
        let spec = BenchmarkSpec::new_hlapi_ops(
            HlIntegerOp::Add,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some(&Ty("FheUint64")),
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
            BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Mul))),
            Backend::Cuda,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some(&Ty("FheUint128")),
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
            BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Add))),
            Backend::Hpu,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some(&Ty("FheUint64")),
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
            Some(&Ty("FheUint64")),
            BenchmarkMetric::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
        );
    }

    #[test]
    fn hlapi_no_type_name() {
        let spec = BenchmarkSpec::new_hlapi_ops(
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
    fn integer_ops_latency() {
        let spec = BenchmarkSpec::new_integer_ops(
            IntegerOpBySign::Unsigned(IntegerOp::AddParallelized),
            "PARAM_MESSAGE_2_CARRY_2",
            Some(&Ty("64_bits")),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::integer::ops::unsigned::add_parallelized::PARAM_MESSAGE_2_CARRY_2::64_bits"
        );
    }

    #[test]
    fn integer_ops_signed() {
        let spec = BenchmarkSpec::new_integer_ops(
            IntegerOpBySign::Signed(IntegerOp::MulParallelized),
            "PARAM_MESSAGE_2_CARRY_2",
            Some(&Ty("64_bits")),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::integer::ops::signed::mul_parallelized::PARAM_MESSAGE_2_CARRY_2::64_bits"
        );
    }

    #[test]
    fn integer_ops_throughput_with_num_elements() {
        let spec = BenchmarkSpec::new_integer_ops(
            IntegerOpBySign::Unsigned(IntegerOp::SumCiphertextsParallelized),
            "PARAM_MESSAGE_2_CARRY_2",
            Some(&Ty("64_bits")),
            BenchmarkMetric::Throughput,
            Some(5),
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::integer::ops::unsigned::sum_ciphertexts_parallelized::throughput::PARAM_MESSAGE_2_CARRY_2::64_bits::5_elements"
        );
    }

    #[test]
    fn integer_ops_ilog2_serialization() {
        let spec = BenchmarkSpec::new_integer_ops(
            IntegerOpBySign::Unsigned(IntegerOp::CheckedIlog2Parallelized),
            "PARAM_MESSAGE_2_CARRY_2",
            Some(&Ty("8_bits")),
            BenchmarkMetric::Latency,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::integer::ops::unsigned::checked_ilog2_parallelized::PARAM_MESSAGE_2_CARRY_2::8_bits"
        );
    }

    #[test]
    fn hlapi_erc7984_with_num_elements() {
        use crate::tfhe::hlapi::erc7984::{Erc7984, TransferFlavor};

        let spec = BenchmarkSpec::new_hlapi(
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

        let spec = BenchmarkSpec::new_hlapi(
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

        let spec = BenchmarkSpec::new(
            BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Erc7984(Erc7984::Transfer(
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

        let spec = BenchmarkSpec::new_hlapi(
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

        let spec = BenchmarkSpec::new_hlapi(
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
            Some(&Ty("FheUint64")),
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
            BenchPath::Tfhe(TfheLayer::Hlapi(HlapiBench::Dex(Dex::SwapClaim(
                DexFlavor::NoCmux,
            )))),
            Backend::Cuda,
            "PARAM_MESSAGE_2_CARRY_2",
            OperandType::CipherText,
            Some(&Ty("FheUint64")),
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
            Some(&Ty("FheUint64")),
            BenchmarkMetric::PbsCount,
            None,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::dex::swap_request::finalize::pbs_count::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }
}
