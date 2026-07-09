use std::fmt;
use strum::Display;

use crate::tfhe::shortint::ops::Ops;
use crate::tfhe::shortint::transciphering::Transciphering;
use crate::traits::SpecFmt;

pub mod ops;
pub mod transciphering;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintBench {
    Ops(Ops),
    Transciphering(Transciphering),
}

impl ShortintBench {
    fn op(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShortintBench::Ops(op) => write!(f, "::{op}"),
            ShortintBench::Transciphering(op) => op.fmt_spec(f),
        }
    }
}

impl SpecFmt for ShortintBench {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}", self)?;
        self.op(f)
    }
}
