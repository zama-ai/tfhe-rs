pub mod msm;

use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use msm::MsmBench;

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkLayerKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum ZkLayer {
    Msm(MsmBench),
}

impl SpecNode for ZkLayer {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ZkLayer::Msm(bench) => bench,
        })
    }
}

impl FromStr for ZkLayer {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkLayerKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk layer: {head}")))?
        {
            ZkLayerKind::Msm => Ok(Self::Msm(rest.parse()?)),
        }
    }
}
