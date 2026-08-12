mod backend;
mod bench_path;
mod csv_writer;
mod error;
mod measured;
mod metric;
mod parse;
mod segment;
pub mod tfhe;
mod traits;
mod type_name;
pub mod zk;

#[cfg(test)]
mod spec_tests;

pub use backend::{Backend, bench_backend_from_cfg};
pub use bench_path::{BenchPath, BenchPathKind};
pub use csv_writer::CsvResultWriter;
pub use error::SpecParseError;
pub use measured::{MeasuredId, Statistic, measured_name};
pub use metric::{BenchmarkMetric, BenchmarkType, OperandType, get_bench_type};
pub use tfhe::hlapi::HlapiBench;
pub use tfhe::{
    BooleanBench, CoreCryptoBench, HlIntegerOp, IntegerBench, IntegerOp, IntegerOpBySign,
    IntegerOprf, IntegerPackingOp, IntegerRerandMode, ShortintBench, ShortintCastingOp, ShortintOp,
    ShortintPackingOp, TfheLayer,
};
pub use type_name::{CudaKeyswitchConfig, PrecisionTag, TypeName, TypedKeyValue};

use crate::segment::OptionalSegment;
use crate::tfhe::TranscipheringBench;
use crate::zk::ZkLayer;
use crate::zk::msm::MsmBench;
use std::fmt;

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
