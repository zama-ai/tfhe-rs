pub mod dex;
pub mod erc20;

use dex::Dex;
use erc20::Erc20;
use std::fmt;
use strum::Display;

use crate::traits::SpecFmt;

pub use super::hl_integer_op::HlIntegerOp;

/// Benchmark categories within the HLAPI layer.
///
/// Each variant represents a category of benchmarks (ops, erc20, dex, etc.)
/// and carries its own op enum. Adding a new category requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `op()` to return the inner op
///
/// `SpecFmt` is already implemented generically — no change needed there.
#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum HlapiBench {
    Ops(HlIntegerOp),
    Erc20(Erc20),
    Dex(Dex),
}

impl HlapiBench {
    fn op(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HlapiBench::Ops(op) => write!(f, "::{op}"),
            HlapiBench::Erc20(op) => op.fmt_spec(f),
            HlapiBench::Dex(op) => op.fmt_spec(f),
        }
    }
}

impl SpecFmt for HlapiBench {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}", self)?;
        self.op(f)
    }
}
