use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

/// DEX (decentralized exchange) benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(DexKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum Dex {
    SwapRequest(DexFlavor),
    SwapClaim(DexFlavor),
}

impl SpecNode for Dex {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            Dex::SwapRequest(op) => op,
            Dex::SwapClaim(op) => op,
        })
    }
}

impl FromStr for Dex {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match DexKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown dex op: {head}")))?
        {
            DexKind::SwapRequest => Ok(Self::SwapRequest(rest.parse()?)),
            DexKind::SwapClaim => Ok(Self::SwapClaim(rest.parse()?)),
        }
    }
}

#[derive(Debug, Clone, Copy, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum DexFlavor {
    Whitepaper,
    NoCmux,
    Prepare,
    Finalize,
}

impl SpecLeafNode for DexFlavor {}
