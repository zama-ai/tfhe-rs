use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

pub mod aes;
pub mod kreyvium;
pub mod prince;
pub mod trivium;

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use aes::AesFlavor;
use kreyvium::KreyviumFlavor;
use prince::PrinceFlavor;
use trivium::TriviumFlavor;

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(TranscipheringBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum TranscipheringBench {
    Aes(AesFlavor),
    Aes256(AesFlavor),
    Kreyvium(KreyviumFlavor),
    FastKreyvium(KreyviumFlavor),
    Prince(PrinceFlavor),
    Trivium(TriviumFlavor),
}

impl SpecNode for TranscipheringBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            TranscipheringBench::Aes(op) => op,
            TranscipheringBench::Aes256(op) => op,
            TranscipheringBench::Kreyvium(op) => op,
            TranscipheringBench::FastKreyvium(op) => op,
            TranscipheringBench::Prince(op) => op,
            TranscipheringBench::Trivium(op) => op,
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
            TranscipheringBenchKind::Aes256 => Ok(Self::Aes256(rest.parse()?)),
            TranscipheringBenchKind::Kreyvium => Ok(Self::Kreyvium(rest.parse()?)),
            TranscipheringBenchKind::FastKreyvium => Ok(Self::FastKreyvium(rest.parse()?)),
            TranscipheringBenchKind::Prince => Ok(Self::Prince(rest.parse()?)),
            TranscipheringBenchKind::Trivium => Ok(Self::Trivium(rest.parse()?)),
        }
    }
}
