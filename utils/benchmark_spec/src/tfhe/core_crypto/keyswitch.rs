use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(KsVariantKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum KsVariant {
    Gemm(KsIndices),
    Classical(KsIndices),
}

impl SpecNode for KsVariant {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            KsVariant::Gemm(indices) | KsVariant::Classical(indices) => indices,
        })
    }
}

impl FromStr for KsVariant {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match KsVariantKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown keyswitch variant: {head}")))?
        {
            KsVariantKind::Gemm => Ok(Self::Gemm(rest.parse()?)),
            KsVariantKind::Classical => Ok(Self::Classical(rest.parse()?)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum KsIndices {
    TrivialIndices,
    ComplexIndices,
}

impl SpecLeafNode for KsIndices {}
