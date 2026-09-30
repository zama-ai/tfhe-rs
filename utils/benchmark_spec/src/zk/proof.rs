use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

/// Spelled with its prefix: `verify::v2::verify` would read as a typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
pub enum ComputeLoad {
    #[strum(serialize = "compute_load_proof")]
    Proof,
    #[strum(serialize = "compute_load_verify")]
    Verify,
}

impl SpecLeafNode for ComputeLoad {}

/// [`ZkScheme`] is its discriminant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkScheme),
    derive(EnumString, Display, Hash, enum_iterator::Sequence),
    strum(serialize_all = "snake_case")
)]
pub enum ZkProofVariant {
    V1(ComputeLoad),
    V2(ComputeLoad),
}

impl SpecLeafNode for ZkScheme {}

impl ZkProofVariant {
    pub const fn new(scheme: ZkScheme, compute_load: ComputeLoad) -> Self {
        match scheme {
            ZkScheme::V1 => Self::V1(compute_load),
            ZkScheme::V2 => Self::V2(compute_load),
        }
    }

    pub fn compute_load(&self) -> ComputeLoad {
        match *self {
            Self::V1(load) | Self::V2(load) => load,
        }
    }
}

impl SpecNode for ZkProofVariant {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            Self::V1(load) | Self::V2(load) => load,
        })
    }
}

impl FromStr for ZkProofVariant {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkScheme::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk scheme: {head}")))?
        {
            ZkScheme::V1 => Ok(Self::V1(rest.parse()?)),
            ZkScheme::V2 => Ok(Self::V2(rest.parse()?)),
        }
    }
}
