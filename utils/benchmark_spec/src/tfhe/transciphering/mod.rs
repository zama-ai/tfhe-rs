use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

pub mod aes;
pub mod kreyvium;

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use aes::AesFlavor;
use kreyvium::KreyviumFlavor;

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(TranscipheringBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
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

impl FromStr for TranscipheringBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match TranscipheringBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown transciphering bench: {head}")))?
        {
            TranscipheringBenchKind::Aes => Ok(Self::Aes(rest.parse()?)),
            TranscipheringBenchKind::Kreyvium => Ok(Self::Kreyvium(rest.parse()?)),
        }
    }
}
