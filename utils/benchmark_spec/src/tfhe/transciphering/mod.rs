use strum::Display;

pub mod aes;

use crate::traits::SpecNode;
use aes::AesFlavor;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TranscipheringBench {
    Aes(AesFlavor),
}

impl SpecNode for TranscipheringBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            TranscipheringBench::Aes(op) => op,
        })
    }
}
