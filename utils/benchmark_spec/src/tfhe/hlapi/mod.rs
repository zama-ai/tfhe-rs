use std::fmt;
use strum::Display;

use crate::traits::SpecFmt;

pub use super::hl_integer_op::HlIntegerOp;

/// Benchmark categories within the HLAPI layer.
///
/// Each variant represents a category of benchmarks (ops, erc7984, dex, etc.)
/// and carries its own op enum. Adding a new category requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `op()` to return the inner op
///
/// `SpecFmt` is already implemented generically — no change needed there.
#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum HlapiBench {
    Ops(HlIntegerOp),
}

impl HlapiBench {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            HlapiBench::Ops(op) => op,
        }
    }
}

impl SpecFmt for HlapiBench {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}::{}", self, self.op())
    }
}
