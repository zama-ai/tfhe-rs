use core::fmt;

use strum::Display;

use crate::traits::SpecFmt;

/// ERC-7984 token transfer benchmark operations for the HLAPI layer.
#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Erc7984 {
    Transfer(TransferFlavor),
}

impl Erc7984 {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            Erc7984::Transfer(op) => op,
        }
    }
}

impl SpecFmt for Erc7984 {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}::{}", self, self.op())
    }
}

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TransferFlavor {
    Whitepaper,
    NoCmux,
    Overflow,
    Safe,
    HpuOptim,
    HpuSimd,
}
