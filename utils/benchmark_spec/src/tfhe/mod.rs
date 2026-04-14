pub mod hl_integer_op;
pub mod hlapi;
pub mod shortint;

use std::fmt;
use strum::Display;

use crate::traits::SpecFmt;

pub use hl_integer_op::HlIntegerOp;
pub use hlapi::HlapiBench;
pub use shortint::ShortintBench;

/// Layers of the `tfhe` crate.
///
/// Adding a new layer requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `bench()` — the inner type must implement `SpecFmt`
///
/// `SpecFmt` is already implemented generically — no change needed there.
#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum TfheLayer {
    Hlapi(HlapiBench),
    Shortint(ShortintBench),
}

impl TfheLayer {
    fn bench(&self) -> &dyn SpecFmt {
        match self {
            TfheLayer::Hlapi(bench) => bench,
            TfheLayer::Shortint(bench) => bench,
        }
    }
}

impl SpecFmt for TfheLayer {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{self}")?;
        self.bench().fmt_spec(f)
    }
}
