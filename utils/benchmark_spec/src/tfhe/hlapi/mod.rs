pub mod dex;
pub mod erc7984;
pub mod kv_store;
pub mod noise_squash;
pub mod oprf;
pub mod vector_find;

use std::str::FromStr;

use dex::Dex;
use erc7984::Erc7984;
use kv_store::KvStoreOp;
use noise_squash::NoiseSquashingKind;
use oprf::OprfKind;
use strum::{Display, EnumDiscriminants, EnumString};
use vector_find::VectorFindOp;

use crate::error::SpecParseError;
use crate::traits::SpecNode;

pub use super::hl_integer_op::HlIntegerOp;

/// Benchmark categories within the HLAPI layer.
///
/// Each variant represents a category of benchmarks (ops, erc7984, dex, etc.)
/// and carries its own op enum. Adding a new category requires:
/// 1. Add the variant here (strum handles the name)
/// 2. Add a match arm in `child()` returning the inner op as `&dyn SpecNode` (a leaf op enum just
///    needs `impl SpecNode for X {}`).
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(HlapiBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum HlapiBench {
    Ops(HlIntegerOp),
    Erc7984(Erc7984),
    Dex(Dex),
    KvStore(KvStoreOp),
    NoiseSquashing(NoiseSquashingKind),
    Oprf(OprfKind),
    VectorFind(VectorFindOp),
}

impl SpecNode for HlapiBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            HlapiBench::Ops(op) => op,
            HlapiBench::Erc7984(op) => op,
            HlapiBench::Dex(op) => op,
            HlapiBench::KvStore(op) => op,
            HlapiBench::NoiseSquashing(op) => op,
            HlapiBench::Oprf(op) => op,
            HlapiBench::VectorFind(op) => op,
        })
    }
}

impl FromStr for HlapiBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match HlapiBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("Unknown layer: {head}")))?
        {
            HlapiBenchKind::Ops => Ok(Self::Ops(rest.parse()?)),
            HlapiBenchKind::Erc7984 => Ok(Self::Erc7984(rest.parse()?)),
            HlapiBenchKind::Dex => Ok(Self::Dex(rest.parse()?)),
            HlapiBenchKind::KvStore => Ok(Self::KvStore(rest.parse()?)),
            HlapiBenchKind::NoiseSquashing => Ok(Self::NoiseSquashing(rest.parse()?)),
            HlapiBenchKind::Oprf => Ok(Self::Oprf(rest.parse()?)),
            HlapiBenchKind::VectorFind => Ok(Self::VectorFind(rest.parse()?)),
        }
    }
}
