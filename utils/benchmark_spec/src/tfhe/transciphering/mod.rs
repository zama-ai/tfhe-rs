use strum::Display;

pub mod aes;
pub mod kreyvium;

use crate::traits::SpecNode;
use aes::AesFlavor;
use kreyvium::KreyviumFlavor;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TranscipheringBench {
    Aes(AesFlavor),
    Kreyvium(KreyviumFlavor),
}

impl SpecNode for TranscipheringBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            TranscipheringBench::Aes(op) => op,
            TranscipheringBench::Kreyvium(op) => op,
        })
    }
}
