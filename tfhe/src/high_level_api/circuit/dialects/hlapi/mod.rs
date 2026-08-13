mod builder;
mod instruction_set;
mod kinds;
mod type_system;

pub use builder::{BuilderError, BuilderErrorKind, Circuit, CircuitBuilder, Operand, ValueId};
pub use instruction_set::HlInstructionSet;
pub use kinds::{ClearKind, FheIntKind, FheKind, KindConvertError};
pub use type_system::{
    KvKey, KvKeyKind, NonNanF64, NotANumberError, OprfMode, ScalarValue, ValueKind,
};

use zhc_ir::Dialect;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HlApiDialect;

impl Dialect for HlApiDialect {
    type TypeSystem = ValueKind;
    type InstructionSet = HlInstructionSet;
}
