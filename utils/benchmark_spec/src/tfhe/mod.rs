pub mod atomic_op;
pub mod hlapi;

use std::fmt;
use strum::Display;

use crate::traits::SpecFmt;

pub use atomic_op::AtomicOp;
pub use hlapi::HlapiBench;

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
}

impl TfheLayer {
    fn bench(&self) -> &dyn SpecFmt {
        match self {
            TfheLayer::Hlapi(bench) => bench,
        }
    }
}

impl SpecFmt for TfheLayer {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{self}")?;
        self.bench().fmt_spec(f)
    }
}
