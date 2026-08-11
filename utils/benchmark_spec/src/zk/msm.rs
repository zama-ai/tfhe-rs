use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(MsmBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum MsmBench {
    G1(MsmFlavor),
    G2(MsmFlavor),
}

impl SpecNode for MsmBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            MsmBench::G1(op) => op,
            MsmBench::G2(op) => op,
        })
    }
}

impl FromStr for MsmBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match MsmBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown msm bench: {head}")))?
        {
            MsmBenchKind::G1 => Ok(Self::G1(rest.parse()?)),
            MsmBenchKind::G2 => Ok(Self::G2(rest.parse()?)),
        }
    }
}

impl MsmBench {
    pub fn display_name(&self) -> String {
        match self {
            MsmBench::G1(flavor) => format!("MSM_{}_G1", flavor.display_name()),
            MsmBench::G2(flavor) => format!("MSM_{}_G2", flavor.display_name()),
        }
    }
}

#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum MsmFlavor {
    Bls12_446,
}

impl SpecLeafNode for MsmFlavor {}

impl MsmFlavor {
    fn display_name(&self) -> &'static str {
        match self {
            MsmFlavor::Bls12_446 => "BLS12_446",
        }
    }
}
