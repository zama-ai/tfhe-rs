use strum::Display;

use crate::traits::SpecNode;

/// DEX (decentralized exchange) benchmark operations for the HLAPI layer.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
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

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum DexFlavor {
    Whitepaper,
    NoCmux,
    Prepare,
    Finalize,
}

impl SpecNode for DexFlavor {}
