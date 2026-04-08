pub mod dex;
pub mod erc7984;
pub mod kv_store;

use dex::Dex;
use erc7984::Erc7984;
use kv_store::KvStoreOp;
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
    Erc7984(Erc7984),
    Dex(Dex),
    /// Leaf benchmarks with no sub-operations — their name is the full operation.
    DecompNoiseSquashComp,
    /// Leaf benchmarks with no sub-operations — their name is the full operation.
    NoiseSquash,
    KvStore(KvStoreOp),
}

impl HlapiBench {
    fn op(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HlapiBench::Ops(op) => write!(f, "::{op}"),
            HlapiBench::Erc7984(op) => op.fmt_spec(f),
            HlapiBench::Dex(op) => op.fmt_spec(f),
            // Leaf benchmarks — no inner op to format.
            HlapiBench::DecompNoiseSquashComp | HlapiBench::NoiseSquash => Ok(()),
            HlapiBench::KvStore(op) => write!(f, "::{op}"),
        }
    }
}

impl SpecFmt for HlapiBench {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}", self)?;
        self.op(f)
    }
}
