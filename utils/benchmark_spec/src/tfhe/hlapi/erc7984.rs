use strum::Display;

use crate::traits::{SpecLeafNode, SpecNode};

/// ERC-7984 token transfer benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, Display)]
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
