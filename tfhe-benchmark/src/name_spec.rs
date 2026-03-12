use crate::utilities::{BenchmarkType, OperandType};
use std::fmt::Display;

pub enum BenchPrefix {
    Hlapi,
    HlapiCuda,
    HlapiHpu,
}

impl Display for BenchPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchPrefix::Hlapi => write!(f, "hlapi::ops"),
            BenchPrefix::HlapiCuda => write!(f, "hlapi::cuda::ops"),
            BenchPrefix::HlapiHpu => write!(f, "hlapi::hpu::ops"),
        }
    }
}

/// Enforces the naming convention for benchmark IDs.
///
/// `func_name`, `type_name` and `param_name` are kept as `&str` because their values
/// are generated dynamically: `func_name` and `type_name` come from `stringify!()` in
/// bench macros, and `param_name` comes from `NamedParam::name()` at runtime.
pub struct NameSpec<'a> {
    pub bench_prefix: BenchPrefix,
    pub func_name: &'a str,
    pub param_name: &'a str,
    pub operand_type: &'a OperandType,
    pub type_name: &'a str,
    pub bench_type: &'a BenchmarkType,
}

impl<'a> NameSpec<'a> {
    pub fn new(
        bench_prefix: BenchPrefix,
        func_name: &'a str,
        param_name: &'a str,
        operand_type: &'a OperandType,
        type_name: &'a str,
        bench_type: &'a BenchmarkType,
    ) -> Self {
        Self {
            bench_prefix,
            func_name,
            param_name,
            operand_type,
            type_name,
            bench_type,
        }
    }
}

impl Display for NameSpec<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.bench_prefix, self.func_name)?;
        if matches!(self.bench_type, BenchmarkType::Throughput) {
            write!(f, "::throughput")?;
        }
        write!(f, "::{}", self.param_name)?;
        if self.operand_type.is_scalar() {
            write!(f, "::scalar")?;
        }
        write!(f, "::{}", self.type_name)
    }
}
