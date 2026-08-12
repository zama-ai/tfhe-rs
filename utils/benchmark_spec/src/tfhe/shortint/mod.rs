pub mod casting;
pub mod ops;
pub mod packing;

use std::str::FromStr;

use ops::ShortintOp;
use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;

pub use casting::ShortintCastingOp;
pub use packing::ShortintPackingOp;

/// Benchmarks of the `shortint` layer. Mixed node: `Ops`, `Casting` and
/// `PackingCompression` carry a child, the other variants are leaves.
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ShortintBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum ShortintBench {
    Ops(ShortintOp),
    Casting(ShortintCastingOp),
    PackingCompression(ShortintPackingOp),
    Oprf,
    // Special ops kept as top-level leaves.
    CarryExtract,
    ProgrammableBootstrap,
    UncompressKey,
    DecompNoiseSquashComp,
}

impl SpecNode for ShortintBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        match self {
            ShortintBench::Ops(op) => Some(op),
            ShortintBench::Casting(op) => Some(op),
            ShortintBench::PackingCompression(op) => Some(op),
            ShortintBench::Oprf
            | ShortintBench::CarryExtract
            | ShortintBench::ProgrammableBootstrap
            | ShortintBench::UncompressKey
            | ShortintBench::DecompNoiseSquashComp => None,
        }
    }
}

impl FromStr for ShortintBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        let kind = ShortintBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown shortint bench: {head}")))?;
        match kind {
            ShortintBenchKind::Ops => Ok(Self::Ops(rest.parse()?)),
            ShortintBenchKind::Casting => Ok(Self::Casting(rest.parse()?)),
            ShortintBenchKind::PackingCompression => Ok(Self::PackingCompression(rest.parse()?)),
            // Leaf variants close the bench path: what follows belongs to the
            // trailing part of the id, not to this node.
            _ if !rest.is_empty() => Err(SpecParseError::Unknown(format!(
                "unexpected {rest:?} after shortint bench {head}"
            ))),
            ShortintBenchKind::Oprf => Ok(Self::Oprf),
            ShortintBenchKind::CarryExtract => Ok(Self::CarryExtract),
            ShortintBenchKind::ProgrammableBootstrap => Ok(Self::ProgrammableBootstrap),
            ShortintBenchKind::UncompressKey => Ok(Self::UncompressKey),
            ShortintBenchKind::DecompNoiseSquashComp => Ok(Self::DecompNoiseSquashComp),
        }
    }
}
