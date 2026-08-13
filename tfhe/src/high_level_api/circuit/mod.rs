pub mod backends;
mod dialects;

pub use dialects::hlapi::{
    BuilderError, BuilderErrorKind, Circuit, CircuitBuilder, ClearKind, FheIntKind, FheKind,
    HlInstructionSet, KindConvertError, KvKey, KvKeyKind, NonNanF64, NotANumberError, Operand,
    OprfMode, ScalarValue, ValueId, ValueKind,
};

pub use backends::cpu::{CpuBackend, CpuError, CpuInputList, CpuOutputError, CpuOutputList};
pub use backends::ExecutionBackend;

#[cfg(test)]
mod test_cases;
