use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

/// ERC-7984 token transfer benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, Display, EnumDiscriminants, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(Erc7984Kind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum Erc7984 {
    Transfer(TransferFlavor),
}

impl SpecNode for Erc7984 {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            Erc7984::Transfer(op) => op,
        })
    }
}

impl FromStr for Erc7984 {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match Erc7984Kind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown erc7984 op: {head}")))?
        {
            Erc7984Kind::Transfer => Ok(Self::Transfer(rest.parse()?)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum TransferFlavor {
    Whitepaper,
    NoCmux,
    Overflow,
    Safe,
    HpuOptim,
    HpuSimd,
}

impl SpecLeafNode for TransferFlavor {}
