pub mod ops;

use std::str::FromStr;

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};
use ops::IntegerOp;
use strum::{Display, EnumDiscriminants, EnumString};

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

/// GLWE packing-compression operations (integer layer).
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerPackingOp {
    Pack,
    Unpack,
}

impl SpecLeafNode for IntegerPackingOp {}

/// Oblivious PRF flavors (integer layer).
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerOprf {
    Unsigned,
    UnsignedBounded,
}

impl SpecLeafNode for IntegerOprf {}

/// Re-randomization modes.
#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum IntegerRerandMode {
    LegacyKeyswitch,
    NoKeyswitch,
}

impl SpecLeafNode for IntegerRerandMode {}

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
