pub mod oprf;
pub mod ops;
pub mod packing;
pub mod rerand;

use std::str::FromStr;

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use ops::IntegerOp;
use strum::{Display, EnumDiscriminants, EnumString};

pub use oprf::IntegerOprf;
pub use packing::IntegerPackingOp;
pub use rerand::IntegerRerandMode;

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(IntegerOpBySignKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum IntegerOpBySign {
    Unsigned(IntegerOp),
    Signed(IntegerOp),
}

impl SpecNode for IntegerOpBySign {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            IntegerOpBySign::Unsigned(op) | IntegerOpBySign::Signed(op) => op,
        })
    }
}

impl FromStr for IntegerOpBySign {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match IntegerOpBySignKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown integer signedness: {head}")))?
        {
            IntegerOpBySignKind::Unsigned => Ok(Self::Unsigned(rest.parse()?)),
            IntegerOpBySignKind::Signed => Ok(Self::Signed(rest.parse()?)),
        }
    }
}

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(IntegerBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum IntegerBench {
    Ops(IntegerOpBySign),
    PackingCompression(IntegerPackingOp),
    Oprf(IntegerOprf),
    Rerand(IntegerRerandMode),
}

impl SpecNode for IntegerBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            IntegerBench::Ops(signedness) => signedness,
            IntegerBench::PackingCompression(op) => op,
            IntegerBench::Oprf(kind) => kind,
            IntegerBench::Rerand(mode) => mode,
        })
    }
}

impl FromStr for IntegerBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match IntegerBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown integer bench: {head}")))?
        {
            IntegerBenchKind::Ops => Ok(Self::Ops(rest.parse()?)),
            IntegerBenchKind::PackingCompression => Ok(Self::PackingCompression(rest.parse()?)),
            IntegerBenchKind::Oprf => Ok(Self::Oprf(rest.parse()?)),
            IntegerBenchKind::Rerand => Ok(Self::Rerand(rest.parse()?)),
        }
    }
}
