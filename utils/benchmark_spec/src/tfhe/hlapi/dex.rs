use core::fmt;

use strum::Display;

use crate::traits::SpecFmt;

/// DEX (decentralized exchange) benchmark operations for the HLAPI layer.
#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Dex {
    SwapRequest(DexFlavor),
    SwapClaim(DexFlavor),
}

impl Dex {
    fn op(&self) -> &dyn fmt::Display {
        match self {
            Dex::SwapRequest(op) => op,
            Dex::SwapClaim(op) => op,
        }
    }
}

impl SpecFmt for Dex {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}::{}", self, self.op())
    }
}

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum DexFlavor {
    Whitepaper,
    NoCmux,
    Prepare,
    Finalize,
}
