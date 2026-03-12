mod backend;
mod bench_crate;
pub mod tfhe;
mod traits;

pub use backend::Backend;
pub use bench_crate::BenchCrate;
use serde::Serialize;
use std::{env, fmt};
pub use tfhe::hlapi::HlapiBench;
pub use tfhe::{HlIntegerOp, TfheLayer};

#[derive(Serialize)]
pub enum OperandType {
    CipherText,
    PlainText,
}

impl OperandType {
    pub fn is_scalar(&self) -> bool {
        matches!(self, OperandType::PlainText)
    }
}

#[derive(Serialize)]
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
    use std::sync::OnceLock;
    static BENCH_TYPE: OnceLock<BenchmarkType> = OnceLock::new();
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap())
}

/// Enforces the naming convention for benchmark IDs.
///
/// ```text
/// {crate}::{layer}::{bench}::{op}(::{backend})?(::throughput)?::{param}(::scalar)?(::{type})?
/// ```
///
/// `param_name` and `type_name` are kept as `&str` because their values
/// are generated dynamically: `type_name` comes from `stringify!()` in
/// bench macros, and `param_name` comes from `NamedParam::name()` at runtime.
pub struct BenchmarkSpec<'a> {
    pub bench_crate: BenchCrate,
    pub backend: Backend,
    pub param_name: &'a str,
    pub operand_type: &'a OperandType,
    pub type_name: Option<&'a str>,
    pub bench_type: &'a BenchmarkType,
}

impl<'a> BenchmarkSpec<'a> {
    pub fn new(
        bench_crate: BenchCrate,
        backend: Backend,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a str>,
        bench_type: &'a BenchmarkType,
    ) -> Self {
        Self {
            bench_crate,
            backend,
            param_name,
            operand_type,
            type_name,
            bench_type,
        }
    }

    pub fn new_hlapi(
        hlapi_op: HlIntegerOp,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: Option<&'a str>,
        bench_type: &'a BenchmarkType,
    ) -> Self {
        Self {
            bench_crate: BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(hlapi_op))),
            backend: Backend::from_cfg(),
            param_name,
            operand_type,
            type_name,
            bench_type,
        }
    }
}

impl fmt::Display for BenchmarkSpec<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bench_crate.fmt_crate(f)?;
        if !matches!(self.backend, Backend::Cpu) {
            write!(f, "::{}", self.backend)?;
        }
        if matches!(self.bench_type, BenchmarkType::Throughput) {
            write!(f, "::throughput")?;
        }
        write!(f, "::{}", self.param_name)?;
        if self.operand_type.is_scalar() {
            write!(f, "::scalar")?;
        }
        if let Some(type_name) = self.type_name {
            write!(f, "::{type_name}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlapi_cpu_latency() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Add))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            Some("FheUint64"),
            &BenchmarkType::Latency,
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
            &OperandType::CipherText,
            Some("FheUint128"),
            &BenchmarkType::Latency,
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
            &OperandType::CipherText,
            Some("FheUint64"),
            &BenchmarkType::Throughput,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::add::hpu::throughput::PARAM_MESSAGE_2_CARRY_2::FheUint64"
        );
    }

    #[test]
    fn hlapi_scalar() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::LeftShift))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::PlainText,
            Some("FheUint64"),
            &BenchmarkType::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::left_shift::PARAM_MESSAGE_2_CARRY_2::scalar::FheUint64"
        );
    }

    #[test]
    fn hlapi_no_type_name() {
        let spec = BenchmarkSpec::new(
            BenchCrate::Tfhe(TfheLayer::Hlapi(HlapiBench::Ops(HlIntegerOp::Neg))),
            Backend::Cpu,
            "PARAM_MESSAGE_2_CARRY_2",
            &OperandType::CipherText,
            None,
            &BenchmarkType::Latency,
        );
        assert_eq!(
            spec.to_string(),
            "tfhe::hlapi::ops::neg::PARAM_MESSAGE_2_CARRY_2"
        );
    }
}
