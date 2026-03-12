use std::fmt;
use strum::Display;

use super::backend::Backend;

/// HLAPI operations.
#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum HlapiOp {
    Add,
    Bitand,
    Bitor,
    Bitxor,
    CheckedIlog2,
    CountOnes,
    CountZeros,
    Div,
    DivRem,
    Eq,
    Flip,
    Ge,
    Gt,
    IfThenElse,
    Ilog2,
    IsEven,
    IsOdd,
    Le,
    LeadingOnes,
    LeadingZeros,
    LeftRotate,
    LeftShift,
    Lt,
    Max,
    Min,
    Mul,
    Ne,
    Neg,
    Not,
    OverflowingAdd,
    OverflowingMul,
    OverflowingNeg,
    OverflowingSub,
    Rem,
    ReverseBits,
    RightRotate,
    RightShift,
    Sub,
    Sum,
    TrailingOnes,
    TrailingZeros,
}

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum OpsLayer {
    Ops(HlapiOp),
}

impl OpsLayer {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            OpsLayer::Ops(op) => op,
        }
    }

    pub(crate) fn fmt_with_backend(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{self}")?;
        write!(f, "::{}", self.op())
    }
}

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum TfheLayer {
    Hlapi(OpsLayer),
}

impl TfheLayer {
    fn op(&self) -> &OpsLayer {
        match self {
            TfheLayer::Hlapi(op) => op,
        }
    }

    pub(crate) fn fmt_with_backend(
        &self,
        f: &mut fmt::Formatter<'_>,
        backend: &Backend,
    ) -> fmt::Result {
        write!(f, "{self}")?;
        if !matches!(backend, Backend::Cpu) {
            write!(f, "::{backend}")?;
        }
        self.op().fmt_with_backend(f)
    }
}
