use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use crate::zk::proof::{ZkProofVariant, ZkProofVariantKind};

/// What a proven compact ciphertext list benchmark measures: a step of the
/// zero-knowledge flow, or one of the objects that flow produces.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkPkeBenchKind),
    derive(EnumString, Display, Hash),
    strum(serialize_all = "snake_case")
)]
pub enum ZkPkeBench {
    /// Building a proven list.
    Proof(ZkProofVariant),
    Verify(ZkProofVariant),
    VerifyAndExpand(ZkProofVariant),
    /// Expanding a list without verifying it first.
    OnlyExpand(ZkProofVariant),
    /// The serialized proven list.
    ProvenList(ZkProofVariant),
    /// The common reference string.
    Crs(ZkProofVariantKind),
}

impl ZkPkeBench {
    pub fn variant(&self) -> Option<ZkProofVariant> {
        match *self {
            ZkPkeBench::Proof(variant)
            | ZkPkeBench::Verify(variant)
            | ZkPkeBench::VerifyAndExpand(variant)
            | ZkPkeBench::OnlyExpand(variant)
            | ZkPkeBench::ProvenList(variant) => Some(variant),
            ZkPkeBench::Crs(_) => None,
        }
    }
}

impl SpecNode for ZkPkeBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ZkPkeBench::Proof(variant)
            | ZkPkeBench::Verify(variant)
            | ZkPkeBench::VerifyAndExpand(variant)
            | ZkPkeBench::OnlyExpand(variant)
            | ZkPkeBench::ProvenList(variant) => variant,
            ZkPkeBench::Crs(scheme) => scheme,
        })
    }
}

impl FromStr for ZkPkeBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkPkeBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk pke bench: {head}")))?
        {
            ZkPkeBenchKind::Proof => Ok(Self::Proof(rest.parse()?)),
            ZkPkeBenchKind::Verify => Ok(Self::Verify(rest.parse()?)),
            ZkPkeBenchKind::VerifyAndExpand => Ok(Self::VerifyAndExpand(rest.parse()?)),
            ZkPkeBenchKind::OnlyExpand => Ok(Self::OnlyExpand(rest.parse()?)),
            ZkPkeBenchKind::ProvenList => Ok(Self::ProvenList(rest.parse()?)),
            ZkPkeBenchKind::Crs => Ok(Self::Crs(rest.parse()?)),
        }
    }
}
