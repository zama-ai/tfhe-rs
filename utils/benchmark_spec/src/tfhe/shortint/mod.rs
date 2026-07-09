use strum::Display;

use crate::tfhe::shortint::ops::Ops;
use crate::tfhe::shortint::transciphering::Transciphering;
use crate::traits::SpecNode;

pub mod ops;
pub mod transciphering;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ShortintBench {
    Ops(Ops),
    Transciphering(Transciphering),
}

impl SpecNode for ShortintBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ShortintBench::Ops(op) => op,
            ShortintBench::Transciphering(op) => op,
        })
    }
}
