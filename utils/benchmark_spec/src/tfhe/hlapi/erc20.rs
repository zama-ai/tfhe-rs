use core::fmt;

use strum::Display;

use crate::traits::SpecFmt;

/// ERC-20 token transfer benchmark operations for the HLAPI layer.
#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Erc20 {
    Transfer(TransferOp),
}

impl Erc20 {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            Erc20::Transfer(op) => op,
        }
    }
}

impl SpecFmt for Erc20 {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}::{}", self, self.op())
    }
}

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TransferOp {
    Whitepaper,
    NoCmux,
    Overflow,
    Safe,
    HpuOptim,
    HpuSimd,
}
